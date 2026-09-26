// nx-dauth : sert la chaîne d'authentification device/app d'une VRAIE Switch (fw 22.5.0)
// pour Nextendo, en auto-signant tous les tokens (aucun Nintendo dans la boucle).
//
// Un seul binaire sert 4 hôtes (routés par un reverse-proxy en HostSNI + TLS passthrough) :
//   dauth-lp1.ndas.srv.nintendo.net   POST /v8/challenge, /v8/device_auth_tokens, /v8/edge_tokens
//   dcert-lp1.ndas.srv.nintendo.net   GET  /keys   (JWKS de vérif du device_auth_token)
//   aauth.hac.lp1.ndas.srv.nintendo.net  POST /v5/application_auth_token
//   acert-lp1.ndas.srv.nintendo.net   GET  /keys   (JWKS de vérif de l'application_auth_token)
//
// Clé du montage : les device_auth_token / application_auth_token sont des JWT RS256 dont
// l'URL `jku` (dcert/acert) pointe vers CE serveur -> la console valide la signature contre
// NOTRE clé publique, jamais une clé Nintendo gravée. Le `mac`/`challenge` envoyés par la
// console sont IGNORÉS (on émet notre propre token, on ne re-vérifie pas la crypto device).
// TLS configuré ClientAuth=NoClientCert : la console présente son cert PRODINFO (mTLS dauth),
// on l'ignore et on répond quand même. Le cert serveur est self-signed (accepté via
// disable_ca_verification côté console).
package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

func getenv(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

// --- passage obligé par la mise à jour (2026-08-16) ---------------------------
//
// Nintendo encode la version d'un jeu comme un entier interne, multiple de 65536
// (le "vXXXXXX" des noms de fichier NSP/dump). Lu directement sur nos propres
// dumps, pas deviné :
//   ARMS                base v0, mise à jour 5.5.1 -> 1245184
//   Mario Tennis Aces    base v0, mise à jour 3.1.1 ->  851968
//
// Ce n'est PAS un contrôle NEX : nextendo-nex ne reçoit jamais la version du
// client sur le fil, NexVersion n'existe que côté serveur (voir settings.go).
// C'est ICI, dans l'échange application_auth_token — qui a lieu AVANT que le jeu
// touche NEX — que la console transmet réellement sa version, via le champ
// standard `application_version`. C'est le seul point d'accroche qui existe.
type versionRule struct {
	min     int
	enforce bool
}

var minAppVersion = map[string]versionRule{
	"01009b500007c000": {1245184, false}, // ARMS
	"0100bde00862a000": {851968, false},  // Mario Tennis Aces
	"01006a800016e000": {2031616, true},  // Super Smash Bros. Ultimate 13.0.5
	"0100770008dd8000": {262144, true},   // Monster Hunter Generations Ultimate 1.4.0
}

// versionGateEnforce : par défaut on se contente de LOGGUER ce que la console
// envoie réellement dans application_version, sans jamais rien refuser — le
// format exact de ce champ (est-ce vraiment cet entier brut ?) n'a encore
// jamais été confirmé sur une vraie requête. Mettre NEXTENDO_VERSION_GATE=1
// une fois qu'une vraie capture aura confirmé la forme du champ.
func versionGateEnforced() bool {
	if getenv("NEXTENDO_VERSION_GATE", "") == "1" {
		return true
	}
	_, err := os.Stat(getenv("NX_DATA", "/data") + "/version_gate_enforce")
	return err == nil
}

// Consoles send application_version as 8 hex digits, e.g. "001f0000" for 13.0.5.
func parseAppVersion(s string) (int, error) {
	if len(s) != 8 {
		return 0, fmt.Errorf("want 8 hex digits, got %q", s)
	}
	n, err := strconv.ParseUint(s, 16, 32)
	return int(n), err
}

func b64url(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func randBytes(n int) []byte {
	b := make([]byte, n)
	rand.Read(b)
	return b
}

func randB64(n int) string { return b64url(randBytes(n)) }

func uuid4() string {
	b := randBytes(16)
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// loadOrGenKey loads a persisted RSA key, or generates + persists one so the JWKS stays
// stable across restarts (the console may cache the kid->key mapping).
func loadOrGenKey(path string) *rsa.PrivateKey {
	if data, err := os.ReadFile(path); err == nil {
		if block, _ := pem.Decode(data); block != nil {
			if k, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
				if rk, ok := k.(*rsa.PrivateKey); ok {
					return rk
				}
			}
			if k, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
				return k
			}
		}
	}
	k, _ := rsa.GenerateKey(rand.Reader, 2048)
	der, _ := x509.MarshalPKCS8PrivateKey(k)
	_ = os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600)
	log.Printf("[nx-dauth] generated new RSA key at %s", path)
	return k
}

func jwksFor(pub *rsa.PublicKey, kid string) []byte {
	eb := big.NewInt(int64(pub.E)).Bytes()
	out, _ := json.Marshal(map[string]any{"keys": []map[string]any{{
		"kty": "RSA", "use": "sig", "alg": "RS256", "kid": kid,
		"n": b64url(pub.N.Bytes()), "e": b64url(eb),
	}}})
	return out
}

func signJWT(header, payload map[string]any, key *rsa.PrivateKey) string {
	hb, _ := json.Marshal(header)
	pb, _ := json.Marshal(payload)
	in := b64url(hb) + "." + b64url(pb)
	sum := sha256.Sum256([]byte(in))
	sig, _ := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	return in + "." + b64url(sig)
}

// loadCA charge la CA Nextendo (ca.pem + ca.key) depuis un dossier, pour signer notre cert
// serveur avec elle. Renvoie une erreur si absente (-> fallback auto-signé).
func loadCA(dir string) (*x509.Certificate, *rsa.PrivateKey, error) {
	certPEM, err := os.ReadFile(dir + "/ca.pem")
	if err != nil {
		return nil, nil, err
	}
	keyPEM, err := os.ReadFile(dir + "/ca.key")
	if err != nil {
		return nil, nil, err
	}
	cb, _ := pem.Decode(certPEM)
	if cb == nil {
		return nil, nil, fmt.Errorf("ca.pem invalide")
	}
	caCert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		return nil, nil, err
	}
	kb, _ := pem.Decode(keyPEM)
	if kb == nil {
		return nil, nil, fmt.Errorf("ca.key invalide")
	}
	if k, e := x509.ParsePKCS8PrivateKey(kb.Bytes); e == nil {
		if rk, ok := k.(*rsa.PrivateKey); ok {
			return caCert, rk, nil
		}
	}
	if rk, e := x509.ParsePKCS1PrivateKey(kb.Bytes); e == nil {
		return caCert, rk, nil
	}
	return nil, nil, fmt.Errorf("ca.key type non supporté")
}

func genSelfSigned(hosts []string) tls.Certificate {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(time.Now().Unix()),
		Subject:      pkix.Name{CommonName: hosts[0], Organization: []string{"Nextendo"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     hosts,
	}
	// Si la CA Nextendo est disponible, on SIGNE le cert avec elle -> les consoles qui font
	// confiance à la CA Nextendo (sans tout désactiver) acceptent nx-dauth (fin des
	// "bad certificate" système -> 2123-0011). Sinon fallback auto-signé (compat plein-disable).
	if caCert, caKey, err := loadCA(getenv("NX_CA_DIR", "/data")); err == nil {
		if der, e := x509.CreateCertificate(rand.Reader, &tmpl, caCert, &key.PublicKey, caKey); e == nil {
			log.Printf("[nx-dauth] cert serveur signé par la CA Nextendo ✓")
			return tls.Certificate{Certificate: [][]byte{der, caCert.Raw}, PrivateKey: key}
		}
	}
	log.Printf("[nx-dauth] cert serveur AUTO-SIGNÉ (CA Nextendo absente) — dépend de disable_ca_verification")
	der, _ := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func main() {
	dataDir := getenv("NX_DATA", "/data")
	dcertKey := loadOrGenKey(dataDir + "/dcert_key.pem")
	acertKey := loadOrGenKey(dataDir + "/acert_key.pem")
	dcertKid := getenv("DCERT_KID", "nx-dcert-1")
	acertKid := getenv("ACERT_KID", "nx-acert-1")
	dcertJWKS := jwksFor(&dcertKey.PublicKey, dcertKid)
	acertJWKS := jwksFor(&acertKey.PublicKey, acertKid)

	// Identité device synthétique (étape 1 : passer 2181-3100 ; on la liera au compte Nextendo
	// à l'étape BAAS/NEX). Rien en aval ne la vérifie contre Nintendo.
	deviceID := getenv("NX_DEVICE_ID", "4e457800deadbeef")
	serial := getenv("NX_SERIAL", "XAW10000000000")
	x5t := getenv("NX_X5T", "lkYHqHf2uXjNZ2UeDnW83GT_wa3-dH1KtPLVgxao3Rs")

	mkDeviceToken := func(clientID string) string {
		now := time.Now().Unix()
		return signJWT(
			map[string]any{"jku": "https://dcert-lp1.ndas.srv.nintendo.net/keys", "kid": dcertKid, "typ": "JWT", "alg": "RS256"},
			map[string]any{
				"sub": deviceID, "iss": "dauth-lp1.ndas.srv.nintendo.net", "aud": clientID,
				"exp": now + 86400, "iat": now - 600, "jti": uuid4(),
				"nintendo": map[string]any{"sn": serial, "pc": "HAC", "dt": "NX Prod 1", "x5t#S256": x5t, "esv": randB64(33), "ist": false},
			}, dcertKey)
	}

	mkAppToken := func(appID, appVer string) string {
		now := time.Now().Unix()
		return signJWT(
			map[string]any{"jku": "https://acert-lp1.ndas.srv.nintendo.net/keys", "kid": acertKid, "typ": "JWT", "alg": "RS256"},
			map[string]any{
				"sub": appID, "iat": now - 600, "exp": now + 86400, "iss": "aauth-lp1.ndas.srv.nintendo.net",
				"jti": uuid4(), "typ": "application_auth_token",
				"dvc": map[string]any{"di": deviceID, "sn": serial},
				"nintendo": map[string]any{
					"ai": appID, "av": appVer, "at": now, "edi": randB64(60), "tbn": randB64(16), "tbh": randB64(32),
					"opp": "MEMBERSHIP_REQUIRED", "ph": "SYSTEM",
					"di": deviceID, "sn": serial, "pc": "HAC", "dt": "NX Prod 1", "ist": false, "esv": randB64(33),
				},
			}, acertKey)
	}

	// contents_authorization_token : JWT émis par dragons, utilisé comme `cert` dans l'aauth
	// DIGITAL. Notre aauth ignore le cert, mais on émet un JWT valide-format au cas où la
	// console le vérifierait (jku -> acert/keys qu'on sert déjà).
	mkContentsToken := func(appID string) string {
		now := time.Now().Unix()
		return signJWT(
			map[string]any{"jku": "https://acert-lp1.ndas.srv.nintendo.net/keys", "kid": acertKid, "typ": "JWT", "alg": "RS256"},
			map[string]any{
				"sub": appID, "iss": "dragons.hac.lp1.dragons.nintendo.net",
				"iat": now - 600, "exp": now + 86400, "jti": uuid4(), "typ": "contents_authorization_token",
				"nintendo": map[string]any{"ai": appID, "di": deviceID, "sn": serial},
			}, acertKey)
	}

	handler := func(w http.ResponseWriter, r *http.Request) {
		host := r.Host
		if i := strings.IndexByte(host, ':'); i >= 0 {
			host = host[:i]
		}
		p := r.URL.Path
		log.Printf("[nx-dauth] %s %s%s", r.Method, host, p)
		w.Header().Set("Content-Type", "application/json")

		switch {
		case strings.HasPrefix(host, "dcert") && p == "/keys":
			w.Write(dcertJWKS)
			return
		case strings.HasPrefix(host, "acert") && p == "/keys":
			w.Write(acertJWKS)
			return

		case strings.HasPrefix(host, "dauth") && p == "/v8/challenge":
			json.NewEncoder(w).Encode(map[string]any{"challenge": randB64(33), "data": randB64(16)})
			return

		case strings.HasPrefix(host, "dauth") && p == "/v8/device_auth_tokens":
			var req struct {
				TokenRequests []struct {
					ClientID string `json:"client_id"`
				} `json:"token_requests"`
			}
			r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1 MB limit
			body, _ := io.ReadAll(r.Body)
			json.Unmarshal(body, &req)
			results := make([]map[string]any, 0, len(req.TokenRequests))
			for _, tr := range req.TokenRequests {
				results = append(results, map[string]any{"client_id": tr.ClientID, "device_auth_token": mkDeviceToken(tr.ClientID), "expires_in": 86400})
			}
			json.NewEncoder(w).Encode(map[string]any{"results": results})
			return

		case strings.HasPrefix(host, "dauth") && p == "/v8/edge_tokens":
			var req struct {
				TokenRequests []struct {
					ClientID string `json:"client_id"`
					VendorID string `json:"vendor_id"`
				} `json:"token_requests"`
			}
			r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1 MB limit
			body, _ := io.ReadAll(r.Body)
			json.Unmarshal(body, &req)
			exp := time.Now().Unix() + 86400
			results := make([]map[string]any, 0, len(req.TokenRequests))
			for _, tr := range req.TokenRequests {
				dtoken := fmt.Sprintf("exp=%d~acl=%%2F%%2A~data=sub=%s.sn=%s.pc=HAC.id=%s~hmac=%s",
					exp, deviceID, serial, uuid4(), hex.EncodeToString(randBytes(32)))
				results = append(results, map[string]any{"client_id": tr.ClientID, "vendor_id": tr.VendorID, "dtoken": dtoken, "expires_in": 86400})
			}
			json.NewEncoder(w).Encode(map[string]any{"results": results})
			return

		case strings.HasPrefix(host, "aauth") && p == "/v5/application_auth_token":
			r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1 MB limit
			r.ParseForm()
			appID := r.FormValue("application_id")
			appVer := r.FormValue("application_version")
			if rule, gated := minAppVersion[strings.ToLower(appID)]; gated {
				min := rule.min
				enforce := rule.enforce && versionGateEnforced()
				v, err := parseAppVersion(appVer)
				// LOGGUÉ à chaque appel sur un titre suivi, qu'on applique ou non — c'est
				// la seule façon de savoir un jour si application_version contient vraiment
				// l'entier attendu, avant de faire confiance à un refus dessus.
				log.Printf("[nx-dauth][VersionGate] app=%s raw_version=%q parsed=%d parse_err=%v min=%d enforce=%v",
					appID, appVer, v, err, min, enforce)
				if enforce {
					if err != nil {
						// Champ absent/illisible : on ne bloque JAMAIS sur une valeur qu'on
						// n'a pas pu interpréter -- refuser à l'aveugle romprait un client
						// légitime dont le champ a une forme qu'on n'a pas prévue.
						log.Printf("[nx-dauth][VersionGate] app=%s: version illisible, on laisse passer", appID)
					} else if v < min {
						w.WriteHeader(http.StatusForbidden)
						json.NewEncoder(w).Encode(map[string]any{
							"errorCode": "application_update_required",
							"detail":    fmt.Sprintf("application_version %d < %d required", v, min),
						})
						log.Printf("[nx-dauth][VersionGate] app=%s REFUSÉ (version=%d < %d)", appID, v, min)
						return
					}
				}
			}
			json.NewEncoder(w).Encode(map[string]any{
				"expires_in":             86400,
				"application_auth_token": mkAppToken(appID, appVer),
				"settings":               []any{},
				"online_play_policy":     "MEMBERSHIP_REQUIRED",
				"policy_handler":         "SYSTEM",
			})
			return

		// --- dragons (service de licence) ---
		case strings.HasPrefix(host, "dragons") && p == "/v2/contents_authorization_token_for_aauth/issue":
			appID := r.Header.Get("Nintendo-Application-Id")
			if appID == "" {
				appID = "0100f8f0000a2000"
			}
			json.NewEncoder(w).Encode(map[string]any{"contents_authorization_token": mkContentsToken(appID)})
			return
		case strings.HasPrefix(host, "dragons") && p == "/v2/elicense_archives/publish":
			// publish de licence : on renvoie une liste vide (rien à vérifier -> la console
			// considère qu'il n'y a pas d'archive de licence en attente). À ajuster si rejeté.
			json.NewEncoder(w).Encode(map[string]any{"elicense_archives": []any{}})
			return
		case strings.HasPrefix(host, "dragons") && p == "/v2/rights/publish_device_linked_elicenses":
			// publish des elicenses liées au device — appelé pendant l'IMPORT d'utilisateur.
			// UNHANDLED (404) = l'import échoue et retry. Liste vide = rien à publier.
			json.NewEncoder(w).Encode(map[string]any{"elicense_archives": []any{}})
			return
		case strings.HasPrefix(host, "dragons") && strings.HasPrefix(p, "/v2/elicense_archives/") && strings.HasSuffix(p, "/report"):
			w.Write([]byte("{}"))
			return
		case strings.HasPrefix(host, "dragons") && p == "/v2/penne_id":
			json.NewEncoder(w).Encode(map[string]any{"id": "nxd" + uuid4(), "password": randB64(24)})
			return
		// elicenses/exercise = EXERCER la licence (= vérifier le DROIT de jouer en ligne). Le vrai
		// Nintendo répond 200 corps VIDE. Sans ça : 404 -> "ne peut pas utiliser les fonctions en
		// ligne" (le système conclut "pas de droit"). C'est LE bloqueur du message d'éligibilité.
		case strings.HasPrefix(host, "dragons") && p == "/v2/elicenses/exercise":
			w.WriteHeader(http.StatusOK)
			return
		case strings.HasPrefix(host, "dragons") && p == "/v2/elicenses/migration_state":
			json.NewEncoder(w).Encode(map[string]any{"state": "COMPLETED", "migration_state": "NONE"})
			return
		}

		log.Printf("[nx-dauth] !! UNHANDLED %s %s%s", r.Method, host, p)
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte("{}"))
	}

	cert := genSelfSigned([]string{
		"dauth-lp1.ndas.srv.nintendo.net",
		"dcert-lp1.ndas.srv.nintendo.net",
		"aauth.hac.lp1.ndas.srv.nintendo.net",
		"aauth-lp1.ndas.srv.nintendo.net",
		"acert-lp1.ndas.srv.nintendo.net",
		"dragons.hac.lp1.dragons.nintendo.net",
		"dragonst.hac.lp1.dragons.nintendo.net",
	})
	srv := &http.Server{
		Addr:    getenv("NX_ADDR", ":443"),
		Handler: http.HandlerFunc(handler),
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
			ClientAuth:   tls.NoClientCert, // dauth est en mTLS : on ignore le cert client
			MinVersion:   tls.VersionTLS12,
		},
	}
	log.Printf("[nx-dauth] dcertKid=%s acertKid=%s deviceID=%s", dcertKid, acertKid, deviceID)
	log.Printf("[nx-dauth] listening %s (dauth + aauth + dcert/acert JWKS)", srv.Addr)
	log.Fatal(srv.ListenAndServeTLS("", ""))
}

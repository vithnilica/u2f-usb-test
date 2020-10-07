package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/flynn/hid"
	"github.com/flynn/u2f/u2fhid"
	"github.com/flynn/u2f/u2ftoken"
)

// https://fidoalliance.org/specs/fido-u2f-v1.2-ps-20170411/fido-u2f-raw-message-formats-v1.2-ps-20170411.html
// https://github.com/google/u2f-ref-code/

func main() {
	msg := []byte(strings.Repeat("ahoj", 100))
	var devs4test []*hid.DeviceInfo
	if devices, errx := u2fhid.Devices(); errx != nil {
		panic(errx)
	} else if len(devices) == 0 {
		fmt.Println("zadne kompatibilni zarizeni neni pripojeno")
	} else {
		for _, d := range devices {
			fmt.Printf("%s %s (%04x:%04x) ", d.Path, d.Product, d.VendorID, d.ProductID)
			//fmt.Printf("%v\n", d)
			if dev, errx := u2fhid.Open(d); errx != nil {
				fmt.Println("neotevre se", errx)
			} else {
				if res, errx := dev.Ping([]byte(msg)); errx != nil {
					fmt.Println("nepinga", errx)
				} else if !bytes.Equal(res, msg) {
					fmt.Printf("vraci blbosti %x, got %x\n", msg, res)
				} else {
					if dev.CapabilityWink {
						//zablikat:)
						if errx := dev.Wink(); errx != nil {
							fmt.Println("neblika!", errx)
							continue
						}
					}
					t := u2ftoken.NewToken(dev)
					if version, errx := t.Version(); errx != nil {
						fmt.Println("verze nejde precist", errx)
					} else {
						fmt.Printf("%s ", version)
						fmt.Println("ok")
						devs4test = append(devs4test, d)
					}
				}
				dev.Close()
			}
		}
	}

	if len(devs4test) > 0 {
		time.Sleep(time.Second)
		fmt.Println("")
		fmt.Println("Spousti se testy registrace a autentizace")
		app := sha256.Sum256([]byte("u2f diag"))
		challenge := sha256.Sum256([]byte("{}"))

	loopdev:
		for _, d := range devs4test {
			var keyHandle []byte
			var pubUser *ecdsa.PublicKey

			fmt.Printf("test registrace pro %s %s (%04x:%04x)\n", d.Path, d.Product, d.VendorID, d.ProductID)
			if dev, errx := u2fhid.Open(d); errx != nil {
				fmt.Println("neotevre se", errx)
			} else {
				t := u2ftoken.NewToken(dev)
				req := u2ftoken.RegisterRequest{Challenge: challenge[:], Application: app[:]}
				var res []byte
				fmt.Print("ceka se na potvrzeni")
				for {
					var err1 error
					res, err1 = t.Register(req)
					if err1 == u2ftoken.ErrPresenceRequired {
						fmt.Print(".")
						time.Sleep(200 * time.Millisecond)
						continue
					} else if err1 != nil {
						fmt.Println()
						fmt.Println("registrace selhala", err1)
						dev.Close()
						continue loopdev
					}
					break
				}
				fmt.Println()
				//fmt.Printf("registered: %x\n", res)
				//fmt.Println("base64 res: ", base64.StdEncoding.EncodeToString(res))
				// https://fidoalliance.org/specs/fido-u2f-v1.2-ps-20170411/fido-u2f-raw-message-formats-v1.2-ps-20170411.html#registration-request-message---u2f_register
				khLen := int(res[66])          //A key handle length byte [1 byte], which specifies the length of the key handle (see below). The value is unsigned (range 0-255).
				keyHandle = res[67 : 67+khLen] //A key handle [length specified in previous field]. This a handle that allows the U2F token to identify the generated key pair. U2F tokens MAY wrap the generated private key and the application id it was generated for, and output that as the key handle.
				userPublicKey := res[1 : 1+65] //A user public key [65 bytes]. This is the (uncompressed) x,y-representation of a curve point on the P-256 NIST elliptic curve.

				curve := elliptic.P256()
				if x, y := elliptic.Unmarshal(curve, userPublicKey); x == nil || y == nil {
					fmt.Println("user public key je nakej vadnej, souradnice se nedaj precist")
				} else {
					if curve.IsOnCurve(x, y) {
						pubUser = &ecdsa.PublicKey{
							Curve: curve,
							X:     x,
							Y:     y,
						}
						fmt.Println("User public key")
						fmt.Printf("publicKey type: %T\n", pubUser)
						if d, _ := x509.MarshalPKIXPublicKey(pubUser); d != nil {
							//openssl ec -in - -text -pubin
							pem.Encode(os.Stdout, &pem.Block{
								Type:  "PUBLIC KEY",
								Bytes: d,
							})
						}

					} else {
						fmt.Println("user public key je nakej vadnej, souradnice nejsou na krivce")
					}
				}

				//An attestation certificate [variable length]. This is a certificate in X.509 DER format. Parsing of the X.509 certificate unambiguously establishes its ending.
				var x struct{ Raw asn1.RawContent }
				if sig, errx := asn1.Unmarshal(res[67+khLen:], &x); errx != nil {
					fmt.Println(errx)
				} else {
					if cert, errx := x509.ParseCertificate(x.Raw); errx != nil {
						fmt.Println(errx)
					} else {
						fmt.Println("Attestation certificate")
						fmt.Println("subject: ", cert.Subject)
						fmt.Println("issuer: ", cert.Issuer)
						fmt.Printf("publicKey type: %T\n", cert.PublicKey)
						//openssl x509 -in - -text
						pem.Encode(os.Stdout, &pem.Block{
							Type:  "CERTIFICATE",
							Bytes: cert.Raw,
						})

						fmt.Printf("signature: %x\n", sig)

						pub, _ := cert.PublicKey.(*ecdsa.PublicKey)
						if pub != nil {
							//validace doslych dat, byl sem zvedavej jak to delaj:)
							hash := sha256.New()
							hash.Write([]byte{0})     //A byte reserved for future use [1 byte] with the value 0x00.
							hash.Write(app[:])        //The application parameter [32 bytes] from the registration request message.
							hash.Write(challenge[:])  //The challenge parameter [32 bytes] from the registration request message.
							hash.Write(keyHandle)     //The above key handle [variable length]. (Note that the key handle length is not included in the signature base string. This doesn't cause confusion in the signature base string, since all other parameters in the signature base string are fixed-length.)
							hash.Write(res[1 : 1+65]) //The above user public key [65 bytes].
							validace := ecdsa.VerifyASN1(pub, hash.Sum(nil), sig)
							fmt.Println("validace podpisu: ", validace)
						}
					}

				}

				fmt.Printf("key handle: %x\n", keyHandle)
				dev.Close()
			}

			if keyHandle == nil {
				continue
			}

			fmt.Printf("test autentizace pro %s %s (%04x:%04x)\n", d.Path, d.Product, d.VendorID, d.ProductID)
			if dev, errx := u2fhid.Open(d); errx != nil {
				fmt.Println("neotevre se", errx)
			} else {
				t := u2ftoken.NewToken(dev)
				req := u2ftoken.AuthenticateRequest{Challenge: challenge[:], Application: app[:], KeyHandle: keyHandle}
				var res *u2ftoken.AuthenticateResponse
				if errx := t.CheckAuthenticate(req); errx != nil {
					fmt.Println("autentizace selhala", errx)
					dev.Close()
					continue loopdev
				}
				fmt.Print("ceka se na potvrzeni")
				for {
					var err1 error
					res, err1 = t.Authenticate(req)
					if err1 == u2ftoken.ErrPresenceRequired {
						fmt.Print(".")
						time.Sleep(200 * time.Millisecond)
						continue
					} else if err1 != nil {
						fmt.Println()
						fmt.Println("autentizace selhala", err1)
						dev.Close()
						continue loopdev
					}
					break
				}
				fmt.Println()
				if res != nil {
					fmt.Printf("user presence: %x\n", res.RawResponse[0:1])
					fmt.Printf("counter: %d\n", res.Counter)
					fmt.Printf("signature: %x\n", res.Signature)

					if pubUser != nil {
						//validace doslych dat, byl sem zvedavej jak to delaj:)
						sig := res.Signature
						hash := sha256.New()
						hash.Write(app[:])               //The application parameter [32 bytes] from the registration request message.
						hash.Write(res.RawResponse[0:1]) //The above user presence byte [1 byte].
						counter := make([]byte, 4, 4)
						binary.BigEndian.PutUint32(counter, res.Counter)
						hash.Write(counter)      //The above counter [4 bytes].
						hash.Write(challenge[:]) //The challenge parameter [32 bytes] from the registration request message.
						validace := ecdsa.VerifyASN1(pubUser, hash.Sum(nil), sig)
						fmt.Println("validace podpisu: ", validace)
					}
				}
				dev.Close()
			}
		}

	}

	fmt.Println("konec")
}

package main

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"strings"
	"time"

	"github.com/flynn/hid"
	"github.com/flynn/u2f/u2fhid"
	"github.com/flynn/u2f/u2ftoken"
)

func main() {
	msg := []byte(strings.Repeat("ahoj", 100))
	var devs4test []*hid.DeviceInfo
	if devices, errx := u2fhid.Devices(); errx != nil {
		panic(errx)
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
		fmt.Println("")
		fmt.Println("spousti se testy registrace a autentizace")
		app := sha256.Sum256([]byte("u2f diag"))
		challenge := sha256.Sum256([]byte("{}"))

	loopdev:
		for _, d := range devs4test {
			var keyHandle []byte
			fmt.Printf("test registrace pro %s %s (%04x:%04x)\n", d.Path, d.Product, d.VendorID, d.ProductID)
			if dev, errx := u2fhid.Open(d); errx != nil {
				fmt.Println("neotevre se", errx)
			} else {
				t := u2ftoken.NewToken(dev)
				req := u2ftoken.RegisterRequest{Challenge: challenge[:], Application: app[:]}
				var res []byte
				fmt.Print("ceka na potvrzeni")
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
				fmt.Printf("registered: %x\n", res)
				res = res[66:]
				khLen := int(res[0])
				res = res[1:]
				keyHandle = res[:khLen]
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
				fmt.Print("ceka na potvrzeni")
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
					fmt.Printf("counter = %d, signature = %x\n", res.Counter, res.Signature)
				}
				dev.Close()
			}
		}

	}

	fmt.Println("konec")
}

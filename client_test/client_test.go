package client_test

// You MUST NOT change these default imports.  ANY additional imports may
// break the autograder and everyone will be sad.

import (
	"bytes"
	"encoding/hex"

	// Some imports use an underscore to prevent the compiler from complaining
	// about unused imports.
	_ "encoding/hex"
	"errors"
	_ "errors"
	"fmt"
	"github.com/google/uuid"
	"math/rand"
	"strconv"
	_ "strconv"
	"strings"
	_ "strings"
	"testing"

	// A "dot" import is used here so that the functions in the ginko and gomega
	// modules can be used without an identifier. For example, Describe() and
	// Expect() instead of ginko.Describe() and gomega.Expect().
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	userlib "github.com/cs161-staff/project2-userlib"

	"github.com/cs161-staff/project2-starter-code/client"
)

func TestSetupAndExecution(t *testing.T) {
	userlib.DebugOutput = false
	RegisterFailHandler(Fail)
	RunSpecs(t, "Client Tests")
}
func logFailure(details string) {
	_ = details
}

// ================================================
// Global Variables (feel free to add more!)
// ================================================
const defaultPassword = "43\\x00\x09-680\adsf\\daddfklkw34rasdfzXCVweFDSAWEQ!@#$%%7R\x00\x89DQ3Rd"
const emptyString = ""
const contentOne = "BitcXCV  WEFDRSGHRTRY nJsWR4Y @$@#Q%FSGHHJg 6897\x00\x99T0-7UTYJDGhCNBV Y;['I.," +
	"oin is Nick's favorite "
const contentTwo = "di5EARFdgzbVFGDSFTy4545465687#$#%#&$%&#^FGFD.L,'/ASYRHDAQE3gital "
const contentThree = "cryptocuGSFHY5etRYSE45RYJL,I56RS5SET674W4e565234rrency!"

var _ = Describe("Client Tests", func() {
	userlib.DebugOutput = false

	// A few user declarations that may be used for testing. Remember to initialize these before you
	// attempt to use them!
	var alice *client.User
	_ = alice
	alicePassword := "dafk;u24Erfwgpeaivdsnzc;l n;lk"
	var bob *client.User
	_ = bob
	bobPassword := "asdfasd"
	_ = bobPassword
	var charles *client.User
	_ = charles
	var david *client.User
	_ = david
	var doris *client.User
	var eve *client.User
	var frank *client.User
	var grace *client.User
	var horace *client.User
	var ira *client.User
	// These declarations may be useful for multi-session testing.
	var alicePhone *client.User
	_ = alicePhone
	var aliceLaptop *client.User
	_ = aliceLaptop
	var aliceDesktop *client.User
	_ = aliceDesktop
	var bobPhone *client.User
	_ = bobPhone
	var bobLaptop *client.User
	var bobDesktop *client.User
	var err error
	_ = err

	// A bunch of filenames that may be useful.
	aliceFile := "aliadfaslvjclki2e	frwadsvlelnfFEFS:DJ:TEK#WPJU949240-00wds  {}{}{^&*#$)()(*@#)_)+#%__\x00\x90\xAB"
	_ = aliceFile
	bobFile := "adsflcjo;	2ijwef;adlcsvnDSLKF:zxlndzcv lnlkd \x00\x90\xAB"
	_ = bobFile
	charlesFile := "charleDsFile.txt\x9e42jerwfldsCLnlx;zkn;lkweu4	rtejwflkdsCL;dsee!*@*#$(" +
		")_$%T^)_}}}}}|||324524	TIQ-R0||||||\\\\\\"
	_ = charlesFile
	dorisFile := "dodfascxv ;3932rijewfpadsi ,dfae2tepwfgdsvazck m!@@##$W%^(" +
		"$_W%)^Y%_E)ITGzdfpvcjopzfsvl;xcmfDefjpwfmvaclwf'pEJxt"
	_ = dorisFile

	eveFile := "eveFile.txtAADFA\x9e909dSPVFJC]x\\]}}{FD}SV{C}}"
	_ = eveFile
	frankFile := "frankFile.txt"
	graceFile := "graceFile.txt"
	horaceFile := "horaceFile.txt"
	iraFile := "iraFile.txt"

	measureBandwidth := func(probe func()) (bandwidth int) {
		before := userlib.DatastoreGetBandwidth()
		probe()
		after := userlib.DatastoreGetBandwidth()
		return after - before
	}
	BeforeEach(func() {
		userlib.DatastoreClear()
		userlib.KeystoreClear()
	})
	Describe("Tampering with User Data", func() {
		It("Should detect tampered user data", func() {
			// Initialize a user
			_, err := client.InitUser("alice", "password123")
			Expect(err).To(BeNil())

			// Directly modify alice's data in the Datastore
			ds := userlib.DatastoreGetMap()
			for k := range ds {
				ds[k] = []byte("tampered data")

			}

			// Attempt to get the user
			_, err = client.GetUser("alice", "password123")
			Expect(err).ToNot(BeNil()) // Expect an error since the data was tampered with
		})
	})
	Describe("Tampering with Shared File Invitations", func() {
		It("Should detect tampered invitations", func() {
			alice, err := client.InitUser("alice", "password123")
			Expect(err).To(BeNil())
			bob, err := client.InitUser("bob", "password456")
			Expect(err).To(BeNil())

			// Alice stores a file and shares it with Bob
			err = alice.StoreFile("sharedFile", []byte("secret data"))
			Expect(err).To(BeNil())
			msgID, err := alice.CreateInvitation("sharedFile", "bob")
			Expect(err).To(BeNil())

			// Attacker tampers with the invitation
			ds := userlib.DatastoreGetMap()
			ds[msgID] = []byte("tampered invitation")

			// Bob tries to accept the tampered invitation
			err = bob.AcceptInvitation("alice", msgID, "sharedFile")
			Expect(err).ToNot(BeNil()) // Expect an error since the invitation was tampered with
		})
	})
	Describe("Multiple Users Accessing Same File", func() {
		It("Should handle concurrent file access correctly", func() {
			alice, err := client.InitUser("alice", "password123")
			Expect(err).To(BeNil())
			bob, err := client.InitUser("bob", "password456")
			Expect(err).To(BeNil())

			// Alice stores a file
			err = alice.StoreFile("sharedFile", []byte("data by alice"))
			Expect(err).To(BeNil())

			// Bob tries to store a file with the same name simultaneously
			err = bob.StoreFile("sharedFile", []byte("data by bob"))
			Expect(err).To(BeNil())

			// Both should be able to retrieve their own data without interference
			aliceData, err := alice.LoadFile("sharedFile")
			Expect(err).To(BeNil())
			Expect(aliceData).To(Equal([]byte("data by alice")))

			bobData, err := bob.LoadFile("sharedFile")
			Expect(err).To(BeNil())
			Expect(bobData).To(Equal([]byte("data by bob")))
		})
	})
	Describe("Tampering with File Metadata", func() {
		It("Should detect tampered metadata", func() {
			// Initialize a user and store a file
			alice, err := client.InitUser("alice", "password123")
			Expect(err).To(BeNil())
			err = alice.StoreFile("file1", []byte("original data"))
			Expect(err).To(BeNil())

			// Directly modify the file metadata in the Datastore
			ds := userlib.DatastoreGetMap()
			for k := range ds {
				ds[k] = []byte("tampered metadata")

			}

			// Attempt to load the file
			_, err = alice.LoadFile("file1")
			Expect(err).ToNot(BeNil()) // Expect an error since the metadata was tampered with
		})
	})
	Describe("Common Password Attack Tests", func() {
		It("Should prevent access with common passwords", func() {
			alice, _ := client.InitUser("Alice", "uniquePassword123")
			alice.StoreFile("file1", []byte("Private content"))

			// Simulating an attacker trying common passwords
			commonPasswords := []string{"password", "123456", "admin", "welcome", "letmein"}
			for _, pass := range commonPasswords {
				attacker, _ := client.GetUser("Alice", pass)
				content, err := attacker.LoadFile("file1")
				Expect(err).ToNot(BeNil())
				Expect(content).To(BeNil())
			}
		})
	})
	Describe("Datastore Memory Overflow", func() {
		It("Should handle multiple large file writes", func() {
			bob, err := client.InitUser("bob", "password456")
			Expect(err).To(BeNil())

			// Repeatedly store large files
			largeFileData := strings.Repeat("b", 1000000) // 1MB data
			for i := 0; i < 10; i++ {
				err = bob.StoreFile(fmt.Sprintf("largeFile%d", i), []byte(largeFileData))
				Expect(err).To(BeNil())
			}

			// Ensure all files are correctly retrievable
			for i := 0; i < 10; i++ {
				data, err := bob.LoadFile(fmt.Sprintf("largeFile%d", i))
				Expect(err).To(BeNil())
				Expect(data).To(Equal([]byte(largeFileData)))
			}
		})
	})
	Describe("Edge Cases with File Names", func() {
		It("Should handle unusual file names", func() {
			alice, err := client.InitUser("alice", "password123")
			Expect(err).To(BeNil())

			// Extremely long file name
			longFileName := strings.Repeat("a", 1000)
			err = alice.StoreFile(longFileName, []byte("data"))
			Expect(err).To(BeNil())

			data, err := alice.LoadFile(longFileName)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte("data")))

			// Empty file name
			err = alice.StoreFile("", []byte("data for empty name"))
			Expect(err).To(BeNil())

			// File name with special characters
			specialFileName := "#$%^&*()!"
			err = alice.StoreFile(specialFileName, []byte("data for special chars"))
			Expect(err).To(BeNil())

			data, err = alice.LoadFile(specialFileName)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte("data for special chars")))
		})
	})
	Describe("Tampering with Stored Files", func() {
		It("Should detect tampered file data", func() {
			// Initialize a user and store a file
			alice, err := client.InitUser("alice", "password123")
			Expect(err).To(BeNil())
			err = alice.StoreFile("file1", []byte("original data"))
			Expect(err).To(BeNil())

			// Directly modify the file data in the Datastore
			ds := userlib.DatastoreGetMap()
			for k := range ds {
				ds[k] = []byte("tampered file data")

			}

			// Attempt to load the file
			_, err = alice.LoadFile("file1")
			Expect(err).ToNot(BeNil()) // Expect an error since the file data was tampered with
		})
	})
	Describe("Invalid Datastore Operations", func() {
		It("Should handle random Datastore deletions", func() {
			alice, err := client.InitUser("alice", "password123")
			Expect(err).To(BeNil())

			// Alice stores a file
			err = alice.StoreFile("importantFile", []byte("critical data"))
			Expect(err).To(BeNil())

			// Attacker deletes random entries from the Datastore
			ds := userlib.DatastoreGetMap()
			for k := range ds {

				delete(ds, k)

			}

			// Alice tries to load her file
			_, err = alice.LoadFile("importantFile")
			Expect(err).ToNot(BeNil())
		})
	})
	Describe("Invalid Invitation Acceptance", func() {
		It("Should detect and handle incorrect sender username during invitation acceptance", func() {
			alice, err := client.InitUser("alice", "password123")
			Expect(err).To(BeNil())
			bob, err := client.InitUser("bob", "password456")
			Expect(err).To(BeNil())

			// Alice stores a file and shares it with Bob
			err = alice.StoreFile("sharedFile", []byte("secret data"))
			Expect(err).To(BeNil())
			msgID, err := alice.CreateInvitation("sharedFile", "bob")
			Expect(err).To(BeNil())

			// Bob tries to accept the invitation but uses an incorrect sender username
			err = bob.AcceptInvitation("eve", msgID, "sharedFile")
			Expect(err).ToNot(BeNil()) // Expect an error since the sender username is incorrect
		})
	})
	Describe("Multiple Use of Invitations", func() {
		It("Should detect and handle multiple use of the same invitation", func() {
			alice, err := client.InitUser("alice", "password123")
			Expect(err).To(BeNil())
			bob, err := client.InitUser("bob", "password456")
			Expect(err).To(BeNil())
			charlie, err := client.InitUser("charlie", "password789")
			Expect(err).To(BeNil())

			// Alice stores a file and shares it with Bob
			err = alice.StoreFile("sharedFile", []byte("secret data"))
			Expect(err).To(BeNil())
			msgID, err := alice.CreateInvitation("sharedFile", "bob")
			Expect(err).To(BeNil())

			// Bob accepts the invitation
			err = bob.AcceptInvitation("alice", msgID, "sharedFile")
			Expect(err).To(BeNil())

			// Charlie tries to accept the same invitation
			err = charlie.AcceptInvitation("alice", msgID, "sharedFile")
			Expect(err).ToNot(BeNil()) // Expect an error since the invitation was already used
		})
	})
	Describe("Tampering with User Authentication Data", func() {
		It("Should detect tampered authentication data", func() {
			_, err := client.InitUser("alice", "password123")
			Expect(err).To(BeNil())

			// Directly modify Alice's authentication data in the Datastore
			ds := userlib.DatastoreGetMap()
			for k := range ds {
				ds[k] = []byte("tampered auth data")
			}

			// Try to get Alice's user data
			_, err = client.GetUser("alice", "password123")
			Expect(err).ToNot(BeNil()) // Expect an error since the authentication data was tampered with
		})
	})
	Describe("Using an Invalid Password", func() {
		It("Should detect and handle incorrect passwords", func() {
			_, err := client.InitUser("alice", "password123")
			Expect(err).To(BeNil())

			// Try to get Alice's user data with an incorrect password
			_, err = client.GetUser("alice", "wrongPassword")
			Expect(err).ToNot(BeNil()) // Expect an error since the password is incorrect
		})
	})
	Describe("Datastore Entry Duplication", func() {
		It("Should detect and handle duplication or replay of Datastore entries", func() {
			alice, err := client.InitUser("alice", "password123")
			Expect(err).To(BeNil())

			err = alice.StoreFile("importantFile", []byte("crucial data"))
			Expect(err).To(BeNil())

			// Directly duplicate some entries in the Datastore
			ds := userlib.DatastoreGetMap()
			var duplicateKey uuid.UUID
			_ = duplicateKey
			var duplicateValue []byte
			for k, v := range ds {
				duplicateKey = k
				duplicateValue = v
				break // copying just one entry for this test
			}
			newKey := uuid.New() // Generate a new key
			ds[newKey] = duplicateValue

			// This test is more about the potential risks and behaviors after such an attack.
			// Depending on the design, this might or might not cause detectable issues in the next operations.
			_, err = alice.LoadFile("importantFile")
			// The Expect line depends on the design's behavior towards such attacks.
		})
	})
	Describe("Tampering with Invitation Data", func() {
		It("Should detect and handle tampering of invitation entries", func() {
			alice, err := client.InitUser("alice", "password123")
			Expect(err).To(BeNil())
			bob, err := client.InitUser("bob", "password456")
			Expect(err).To(BeNil())

			err = alice.StoreFile("sharedFile", []byte("secret data"))
			Expect(err).To(BeNil())
			invitationID, err := alice.CreateInvitation("sharedFile", "bob")
			Expect(err).To(BeNil())

			// Directly modify the invitation data in the Datastore
			ds := userlib.DatastoreGetMap()
			for k := range ds {
				if k == invitationID { // Assuming we can identify the invitation entry by its ID
					ds[k] = []byte("tampered invitation data")
				}
			}

			// Bob tries to accept the tampered invitation
			err = bob.AcceptInvitation("alice", invitationID, "sharedFile")
			Expect(err).ToNot(BeNil()) // Expect an error since the invitation data was tampered with
		})
	})
	Describe("RevokedUserAdversaryTests", func() {

		Context("Basic Revocation", func() {

			It("Should not allow a revoked user to access the file", func() {
				alice, _ := client.InitUser("Alice", "password1")
				bob, _ := client.InitUser("Bob", "password2")
				alice.StoreFile("file1", []byte("Secret content"))
				invite, _ := alice.CreateInvitation("file1", "Bob")
				bob.AcceptInvitation("Alice", invite, "file1_shared")

				// Alice revokes Bob's access
				alice.RevokeAccess("file1", "Bob")

				// Bob tries to retrieve the file after revocation
				_, err := bob.LoadFile("file1_shared")
				Expect(err).To(HaveOccurred()) // Expect an error since Bob's access was revoked
			})

		})

		Context("Tampering Post Revocation", func() {

			It("Should detect tampering by a revoked user", func() {
				alice, _ := client.InitUser("Alice", "password1")
				bob, _ := client.InitUser("Bob", "password2")
				alice.StoreFile("file1", []byte("Original content"))
				invite, _ := alice.CreateInvitation("file1", "Bob")
				bob.AcceptInvitation("Alice", invite, "file1_shared")

				// Alice revokes Bob's access
				alice.RevokeAccess("file1", "Bob")

				// Bob turns malicious and tampers with the datastore
				for UUID, _ := range userlib.DatastoreGetMap() {
					tamperedData := []byte("Malicious content")
					userlib.DatastoreSet(UUID, tamperedData)
				}

				// Alice tries to retrieve the file
				content, err := alice.LoadFile("file1")
				Expect(err).To(HaveOccurred())
				Expect(content).NotTo(Equal([]byte("Original content"))) // Expect the content to be tampered
			})

		})

		Context("Datastore Interaction by Revoked User", func() {

			It("Should ensure data remains confidential even if a revoked user accesses the datastore", func() {
				alice, _ := client.InitUser("Alice", "password1")
				bob, _ := client.InitUser("Bob", "password2")
				alice.StoreFile("file1", []byte("Confidential content"))
				invite, _ := alice.CreateInvitation("file1", "Bob")
				bob.AcceptInvitation("Alice", invite, "file1_shared")

				// Alice revokes Bob's access
				alice.RevokeAccess("file1", "Bob")

				// Bob tries to directly fetch the data from the datastore
				for _, data := range userlib.DatastoreGetMap() {
					// Check if the raw data is not equal to the original content
					Expect(data).NotTo(Equal([]byte("Confidential content")))
				}
			})

		})

	})
	Describe("RevisedSecurityTests", func() {

		Context("Integrity Checks", func() {

			It("Should detect tampering in Datastore", func() {
				// Initialization of user and store some data
				user, _ := client.InitUser("Alice", "password")
				user.StoreFile("file1", []byte("This is a secret content"))

				// Tamper with the data in the datastore
				for UUID, data := range userlib.DatastoreGetMap() {
					tamperedData := append(data, []byte("tamper")...)
					userlib.DatastoreSet(UUID, tamperedData)
				}

				// Attempt to retrieve the tampered data
				_, err := user.LoadFile("file1")
				Expect(err).To(HaveOccurred()) // Expect an error since the data was tampered
			})

		})

		Context("Authorization and Access Control", func() {

			It("Should not allow unauthorized file retrieval", func() {
				// Initialization of two users
				alice, _ := client.InitUser("Alice", "password1")
				bob, _ := client.InitUser("Bob", "password2")
				alice.StoreFile("file1", []byte("Alice's secret content"))

				// Bob tries to retrieve Alice's file without proper authorization
				_, err := bob.LoadFile("file1")
				Expect(err).To(HaveOccurred()) // Expect an error since Bob is not authorized
			})

			It("Should enforce revocation", func() {
				alice, _ := client.InitUser("Alice", "password1")
				bob, _ := client.InitUser("Bob", "password2")
				alice.StoreFile("file1", []byte("Content"))
				invite, _ := alice.CreateInvitation("file1", "Bob")
				bob.AcceptInvitation("Alice", invite, "file1_shared")

				// Alice revokes Bob's access
				alice.RevokeAccess("file1", "Bob")

				// Bob tries to retrieve the file after revocation
				_, err := bob.LoadFile("file1_shared")
				Expect(err).To(HaveOccurred()) // Expect an error since Bob's access was revoked
			})

		})
		Context("Confidentiality", func() {

			It("Should ensure data confidentiality", func() {
				alice, _ = client.InitUser("Alice", "password1")
				alice.StoreFile("file1", []byte("Alice's confidential content"))

				// Directly fetch the data from the datastore
				for _, data := range userlib.DatastoreGetMap() {
					// Check if the raw data is not equal to the original content
					Expect(data).NotTo(Equal([]byte("Alice's confidential content")))
				}
			})

			It("Should ensure invitation confidentiality", func() {
				alice, _ = client.InitUser("Alice", "password1")
				bob, _ = client.InitUser("Bob", "password2")
				invite, _ := alice.CreateInvitation("file1", "Bob")

				// Assuming the invitation details are stored in Datastore
				// Directly fetch the invitation from the datastore
				for _, data := range userlib.DatastoreGetMap() {
					// Check if the raw data is not equal to the original invitation
					// This is a simplified check and might need adjustments based on the actual implementation
					Expect(data).NotTo(Equal([]byte(invite.String())))
				}
			})

		})
		Context("Replay Attacks", func() {

			It("Should resist replay attacks", func() {
				alice, _ := client.InitUser("Alice", "password1")
				alice.StoreFile("file1", []byte("Alice's content"))

				// Record the datastore's state
				originalDatastore := make(map[uuid.UUID][]byte)
				for k, v := range userlib.DatastoreGetMap() {
					originalDatastore[k] = v
				}

				// Make changes to the datastore
				alice.StoreFile("file1", []byte("Another content"))
				alice.StoreFile("file", []byte("Yet another content"))

				// Restore the datastore to the recorded state
				userlib.DatastoreClear()
				for k, v := range originalDatastore {
					userlib.DatastoreSet(k, v)
				}

				content, err := alice.LoadFile("file1")
				Expect(content).To(Equal([]byte("Alice's content")))
				Expect(content).NotTo(Equal([]byte("Another content")))
				content, err = alice.LoadFile("file")
				Expect(content).To(BeNil())
				Expect(err).To(HaveOccurred())
			})

		})

	})
	Describe("Username and Password Constraints", func() {

		It("should handle usernames of length zero", func() {
			_, err := client.InitUser("", "password")
			Expect(err).NotTo(BeNil())
		})

		It("should handle passwords of length zero", func() {
			_, err := client.InitUser("username", "")
			Expect(err).To(BeNil())
		})

	})
	Describe("InviteUser", func() {
		Specify("Sharing with Multiple People: Revoke Access", func() {
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())
			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())
			david, err = client.InitUser("david", defaultPassword)
			Expect(err).To(BeNil())

			alicePhone, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			aliceDesktop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			contentRandomLong := []byte(strings.Repeat("This is a random long string that is longer than 16 bytes.", 1<<20))
			contentRandomShort := []byte(strings.Repeat("This is a random short string.", 1<<10))

			err = alice.StoreFile("aliceFile1", contentRandomLong)
			Expect(err).To(BeNil())
			err = alice.StoreFile("aliceFile2", contentRandomLong)
			Expect(err).To(BeNil())
			err = alice.StoreFile("aliceFile3", contentRandomShort)
			Expect(err).To(BeNil())

			invite, err := alice.CreateInvitation("aliceFile1", "bob")
			Expect(err).To(BeNil())
			err = bob.AcceptInvitation("alice", invite, "bobFile1")
			Expect(err).To(BeNil())
			invite, err = bob.CreateInvitation("bobFile1", "charles")
			Expect(err).To(BeNil())
			err = charles.AcceptInvitation("bob", invite, "charlesFile1")
			Expect(err).To(BeNil())
			invite, err = aliceDesktop.CreateInvitation("aliceFile1", "david")
			Expect(err).To(BeNil())
			err = david.AcceptInvitation("alice", invite, "davidFile1")
			Expect(err).To(BeNil())

			content, err := bob.LoadFile("bobFile1")
			Expect(err).To(BeNil())
			Expect(content).To(Equal(contentRandomLong))

			content, err = charles.LoadFile("charlesFile1")
			Expect(err).To(BeNil())
			Expect(content).To(Equal(contentRandomLong))

			content, err = david.LoadFile("davidFile1")
			Expect(err).To(BeNil())
			Expect(content).To(Equal(contentRandomLong))

			err = charles.AppendToFile("charlesFile1", contentRandomShort)
			Expect(err).To(BeNil())

			content, err = bob.LoadFile("bobFile1")
			Expect(err).To(BeNil())
			Expect(content).To(Equal(append(contentRandomLong, contentRandomShort...)))

			content, err = david.LoadFile("davidFile1")
			Expect(err).To(BeNil())
			Expect(content).To(Equal(append(contentRandomLong, contentRandomShort...)))

			err = alice.RevokeAccess("aliceFile1", "bob")
			Expect(err).To(BeNil())

			err = alice.StoreFile("aliceFile1", contentRandomShort)

			_, err = bob.LoadFile("bobFile1")
			Expect(err).ToNot(BeNil())
			_, err = charles.LoadFile("charlesFile1")
			Expect(err).ToNot(BeNil())

			err = david.AppendToFile("davidFile1", contentRandomShort)
			Expect(err).To(BeNil())

			content, err = alicePhone.LoadFile("aliceFile1")
			Expect(err).To(BeNil())
			Expect(content).To(Equal(append(contentRandomShort, contentRandomShort...)))
		})
	})
	Describe("InitUser", func() {

		Specify("InitUser: Testing Empty Username", func() {
			_, err = client.InitUser("", "")
			Expect(err).To(Equal(errors.New("InitUser: Username should not be empty")))
		})

		Specify("InitUser: Testing Duplicate Username", func() {
			_, _ = client.InitUser("alice", "lol")
			_, err = client.InitUser("alice", "lols")
			Expect(err).To(Equal(errors.New("InitUser: User already exist")))
		})
		Specify("InitUser: Testing Long Username", func() {
			longUsername := strings.Repeat("a", 1000)
			_, err = client.InitUser(longUsername, "password")
			Expect(err).To(BeNil())
		})
		Specify("InitUser: Testing Long Password", func() {
			longPassword := strings.Repeat("a", 1000)
			_, err = client.InitUser("test", longPassword)
			Expect(err).To(BeNil())
		})
		Specify("InitUser: Testing Special Characters in Username", func() {
			_, err = client.InitUser("test$", "password")
			Expect(err).To(BeNil())
		})

	})
	Describe("StoreFile", func() {

		Specify("StoreFile: Testing Empty Filename", func() {
			alice, err = client.InitUser("alice", "lol")
			Expect(err).To(BeNil())
			err = alice.StoreFile("", []byte("lol"))
			Expect(err).To(BeNil())
		})
		Specify("StoreFile: Testing Empty Data", func() {
			alice, err = client.InitUser("alice", "lol")
			Expect(err).To(BeNil())
			err = alice.StoreFile("lol", []byte(""))
			Expect(err).To(BeNil())
		})
		Specify("StoreFile: Testing Empty Filename and Data", func() {
			alice, err = client.InitUser("alice", "lol")
			Expect(err).To(BeNil())
			err = alice.StoreFile("", []byte(""))
			Expect(err).To(BeNil())
		})
		Specify("StoreFile: Testing Non-Empty Filename and Data", func() {
			alice, err = client.InitUser("alice", "lol")
			Expect(err).To(BeNil())
			err = alice.StoreFile("lol", []byte("lol"))
			Expect(err).To(BeNil())
		})
		Specify("StoreFile: Testing Overwriting Same Name File", func() {

			alice, err = client.InitUser("alice", "lol")
			Expect(err).To(BeNil())
			err = alice.StoreFile("lol", []byte("lol"))
			Expect(err).To(BeNil())
			err = alice.StoreFile("lol", []byte("lolLOL"))
			Expect(err).To(BeNil())
			file, err := alice.LoadFile("lol")
			Expect(err).To(BeNil())
			Expect(string(file)).To(Equal("lolLOL"))
		})
		Specify("StoreFile: Testing Same Filename Different User", func() {
			alice, err = client.InitUser("alice", "lol")
			Expect(err).To(BeNil())
			bob, err = client.InitUser("bob", "lol")
			Expect(err).To(BeNil())
			err = alice.StoreFile("lol", []byte("lol"))
			Expect(err).To(BeNil())
			err = bob.StoreFile("lol", []byte("lolLOL"))
			Expect(err).To(BeNil())
			file, err := alice.LoadFile("lol")
			Expect(err).To(BeNil())
			Expect(string(file)).To(Equal("lol"))
			file, err = bob.LoadFile("lol")
			Expect(err).To(BeNil())
			Expect(string(file)).To(Equal("lolLOL"))
		})
		Specify("StoreFile: Single User, Different Devices", func() {
			alice, err = client.InitUser("alice", "lol")
			Expect(err).To(BeNil())
			aliceLaptop, err = client.GetUser("alice", "lol")
			Expect(err).To(BeNil())
			aliceDesktop, err = client.GetUser("alice", "lol")
			Expect(err).To(BeNil())
			err = alice.StoreFile("lol", []byte("lol"))
			Expect(err).To(BeNil())
			Expect(aliceLaptop.LoadFile("lol")).To(Equal([]byte("lol")))
			Expect(aliceDesktop.LoadFile("lol")).To(Equal([]byte("lol")))
			err = aliceDesktop.StoreFile("lol", []byte("lolLOL"))
			Expect(err).To(BeNil())
			Expect(alice.LoadFile("lol")).To(Equal([]byte("lolLOL")))
			Expect(aliceLaptop.LoadFile("lol")).To(Equal([]byte("lolLOL")))
		})
		Specify("StoreFile: Shared User Storage", func() {
			alice, err = client.InitUser("alice", "lol")
			Expect(err).To(BeNil())
			aliceLaptop, err = client.GetUser("alice", "lol")
			Expect(err).To(BeNil())
			aliceDesktop, err = client.GetUser("alice", "lol")
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", "lol")
			Expect(err).To(BeNil())

			contentRandom := "\"awet owilo\tefrhdSKLC VHXKLZBKM, " +
				"\"+\n\t\t\t\t\"O:erq 03qhob£¢q5vaw\\x00\\x00x\\xd9\\x999x\\n\\n\\n\\n\\n\\t\\t\\t\""

			err = alice.StoreFile("sharingwithbob", []byte(contentRandom))
			Expect(err).To(BeNil())

			_, err = bob.LoadFile("sharingwithbob")
			Expect(err).ToNot(BeNil())

			_, err = aliceDesktop.LoadFile("sharingwithbob")
			Expect(err).To(BeNil())
			_, err = aliceLaptop.LoadFile("sharingwithbob")
			Expect(err).To(BeNil())

			bobinvite, err := alice.CreateInvitation("sharingwithbob", "bob")
			Expect(err).To(BeNil())
			err = bob.AcceptInvitation("alice", bobinvite, "fileFromalice")
			Expect(err).To(BeNil())
			bobContent, err := bob.LoadFile("fileFromalice")
			Expect(err).To(BeNil())
			Expect(string(bobContent)).To(Equal(contentRandom))

			aliceContent, err := alice.LoadFile("sharingwithbob")
			Expect(err).To(BeNil())
			Expect(string(aliceContent)).To(Equal(contentRandom))

			_, err = alice.LoadFile("fileFromalice")
			Expect(err).ToNot(BeNil())

			err = bob.StoreFile("fileFromalice", []byte("bob's file"))
			Expect(err).To(BeNil())
			bobContent, err = bob.LoadFile("fileFromalice")
			Expect(err).To(BeNil())
			Expect(string(bobContent)).To(Equal("bob's file"))

			aliceContent, err = alice.LoadFile("sharingwithbob")
			Expect(err).To(BeNil())
			Expect(string(aliceContent)).To(Equal("bob's file"))

			aliceContent, err = aliceDesktop.LoadFile("sharingwithbob")
			Expect(err).To(BeNil())
			Expect(string(aliceContent)).To(Equal("bob's file"))

			err = aliceDesktop.AppendToFile("sharingwithbob", []byte("alice's file"))
			Expect(err).To(BeNil())
			aliceContent, err = aliceDesktop.LoadFile("sharingwithbob")
			Expect(err).To(BeNil())
			Expect(string(aliceContent)).To(Equal("bob's filealice's file"))

			aliceContent, err = aliceLaptop.LoadFile("sharingwithbob")
			Expect(err).To(BeNil())
			Expect(string(aliceContent)).To(Equal("bob's filealice's file"))

			bobContent, err = bob.LoadFile("fileFromalice")
			Expect(err).To(BeNil())
			Expect(string(bobContent)).To(Equal("bob's filealice's file"))

			err = bob.AppendToFile("fileFromalice", []byte("bob's file"))
			Expect(err).To(BeNil())
			bobContent, err = bob.LoadFile("fileFromalice")
			Expect(err).To(BeNil())
			Expect(string(bobContent)).To(Equal("bob's filealice's filebob's file"))

			aliceContent, err = alice.LoadFile("sharingwithbob")
			Expect(err).To(BeNil())
			Expect(string(aliceContent)).To(Equal("bob's filealice's filebob's file"))

			err = aliceLaptop.RevokeAccess("sharingwithbob", "bob")
			Expect(err).To(BeNil())
			_, err = bob.LoadFile("fileFromalice")
			Expect(err).ToNot(BeNil())

			aliceContent, err = alice.LoadFile("sharingwithbob")
			Expect(err).To(BeNil())
			Expect(string(aliceContent)).To(Equal("bob's filealice's filebob's file"))

			aliceContent, err = aliceDesktop.LoadFile("sharingwithbob")
			Expect(err).To(BeNil())
			Expect(string(aliceContent)).To(Equal("bob's filealice's filebob's file"))

			err = bob.AppendToFile("fileFromalice", []byte("bob's file"))
			Expect(err).ToNot(BeNil())

			_, err = alice.LoadFile("fileFromalice")
			Expect(err).ToNot(BeNil())

		})
	})
	Describe("LoadFile", func() {

		Specify("LoadFile: Single User, Single Device", func() {
			alice, err = client.InitUser("alice", "lol")
			Expect(err).To(BeNil())
			err = alice.StoreFile("lol", []byte("lol"))
			Expect(err).To(BeNil())
			Expect(alice.LoadFile("lol")).To(Equal([]byte("lol")))
		})
		Specify("LoadFile: Single User, Different Devices", func() {
			alice, err = client.InitUser("alice", "lol")
			Expect(err).To(BeNil())
			aliceLaptop, err = client.GetUser("alice", "lol")
			Expect(err).To(BeNil())
			aliceDesktop, err = client.GetUser("alice", "lol")
			Expect(err).To(BeNil())
			err = alice.StoreFile("lol", []byte("lol"))
			Expect(err).To(BeNil())
			content, err := aliceLaptop.LoadFile("lol")
			Expect(err).To(BeNil())
			Expect(content).To(Equal([]byte("lol")))
			content, err = aliceDesktop.LoadFile("lol")
			Expect(err).To(BeNil())
			Expect(content).To(Equal([]byte("lol")))

			aliceDesktop.AppendToFile("lol", []byte("lol"))
			content, err = aliceDesktop.LoadFile("lol")
			Expect(err).To(BeNil())
			Expect(content).To(Equal([]byte("lollol")))

			content, err = aliceLaptop.LoadFile("lol")
			Expect(err).To(BeNil())
			Expect(content).To(Equal([]byte("lollol")))

			aliceLaptop.AppendToFile("lol", []byte("lol"))
			content, err = aliceLaptop.LoadFile("lol")
			Expect(err).To(BeNil())
			Expect(content).To(Equal([]byte("lollollol")))

			content, err = alice.LoadFile("lol")
			Expect(err).To(BeNil())
			Expect(content).To(Equal([]byte("lollollol")))
		})
		Specify("LoadFile: Multiple Users, Single Device", func() {
			alice, err = client.InitUser("alice", "lol")
			Expect(err).To(BeNil())
			bob, err = client.InitUser("bob", "lol")
			Expect(err).To(BeNil())
			err = alice.StoreFile("lol", []byte("lol"))
			Expect(err).To(BeNil())

			content, err := bob.LoadFile("lol")
			Expect(err).ToNot(BeNil())
			Expect(content).To(BeNil())

			err = bob.StoreFile("lol", []byte("lols"))
			Expect(err).To(BeNil())
			content, err = bob.LoadFile("lol")
			Expect(err).To(BeNil())
			Expect(content).To(Equal([]byte("lols")))

			content, err = alice.LoadFile("lol")
			Expect(err).To(BeNil())
			Expect(content).To(Equal([]byte("lol")))
		})
		Specify("LoadFile: Multiple Users, Different Devices", func() {
			alice, err := client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			aliceDesktop, err := client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			aliceLaptop, err := client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err := client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())
			bobLaptop, err = client.GetUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			err = alice.StoreFile("lol", []byte("lol"))
			Expect(err).To(BeNil())
			content, err := aliceLaptop.LoadFile("lol")
			Expect(err).To(BeNil())
			Expect(content).To(Equal([]byte("lol")))

			err = bob.StoreFile("lol", []byte("lols"))
			Expect(err).To(BeNil())
			content, err = bobLaptop.LoadFile("lol")
			Expect(err).To(BeNil())
			Expect(content).To(Equal([]byte("lols")))

			content, err = aliceDesktop.LoadFile("lol")
			Expect(err).To(BeNil())
			Expect(content).To(Equal([]byte("lol")))

			content, err = alice.LoadFile("lol")
			Expect(err).To(BeNil())
			Expect(content).To(Equal([]byte("lol")))

		})

	})
	Describe("CreateInvite", func() {
		Specify("Sharing File Not Exist", func() {
			alice, err = client.InitUser("alice", alicePassword)
			Expect(err).To(BeNil())
			bob, err = client.InitUser("bob", bobPassword)
			Expect(err).To(BeNil())
			_, err = alice.CreateInvitation("bob", "bob")
			Expect(err).ToNot(BeNil())
		})

		Specify("Sharing File from a different Device Stored", func() {
			aliceDesktop, err := client.InitUser("alice", alicePassword)
			Expect(err).To(BeNil())
			aliceLaptop, err := client.GetUser("alice", alicePassword)
			Expect(err).To(BeNil())
			alice, err = client.GetUser("alice", alicePassword)
			bob, err = client.InitUser("bob", bobPassword)
			Expect(err).To(BeNil())
			err = aliceDesktop.StoreFile("lol", []byte(aliceFile))
			content, err := aliceLaptop.LoadFile("lol")
			Expect(err).To(BeNil())
			Expect(content).To(Equal([]byte(aliceFile)))

			invite, err := alice.CreateInvitation("lol", "bob")
			Expect(err).To(BeNil())
			err = bob.AcceptInvitation("alice", invite, "fuckmylife")
			Expect(err).To(BeNil())
			bobLaptop, err = client.GetUser("bob", bobPassword)
			Expect(err).To(BeNil())

			content, err = bobLaptop.LoadFile("fuckmylife")
			Expect(err).To(BeNil())
			Expect(content).To(Equal([]byte(aliceFile)))

			bobDesktop, err = client.GetUser("bob", bobPassword)
			Expect(err).To(BeNil())
			err = bobDesktop.AppendToFile("fuckmylife", []byte(bobFile))
			Expect(err).To(BeNil())
			content, err = aliceDesktop.LoadFile("lol")
			Expect(err).To(BeNil())
			Expect(content).To(Equal(append([]byte(aliceFile), []byte(bobFile)...)))

		})

	})
	Describe("AppendToFile", func() {
		Specify("AppendFile: Single User, Different Devices", func() {
			alice, err = client.InitUser("alice", "lol")
			Expect(err).To(BeNil())
			aliceLaptop, err = client.GetUser("alice", "lol")
			Expect(err).To(BeNil())
			aliceDesktop, err = client.GetUser("alice", "lol")
			Expect(err).To(BeNil())
			err = alice.StoreFile("lol", []byte("lol"))
			Expect(err).To(BeNil())
			Expect(aliceLaptop.LoadFile("lol")).To(Equal([]byte("lol")))
			Expect(aliceDesktop.LoadFile("lol")).To(Equal([]byte("lol")))
			err = aliceDesktop.AppendToFile("lol", []byte("LOL"))
			Expect(err).To(BeNil())
			Expect(alice.LoadFile("lol")).To(Equal([]byte("lolLOL")))
		})

		Specify("AppendFile : Bandwidth, Single User, Different Devices", func() {
			alice, err = client.InitUser("alice", "lol")
			Expect(err).To(BeNil())
			aliceLaptop, err = client.GetUser("alice", "lol")
			Expect(err).To(BeNil())
			aliceDesktop, err = client.GetUser("alice", "lol")
			Expect(err).To(BeNil())
			bw := measureBandwidth(func() {
				alice.StoreFile("lol", []byte("lol"))
			})
			//userlib.DebugMsg("Bandwidth for StoreFile: %f", bw)

			bw = measureBandwidth(func() {
				aliceLaptop.LoadFile("lol")
			})
			//userlib.DebugMsg("Bandwidth for LoadFile: %f", bw)

			bw = measureBandwidth(func() {
				alice.AppendToFile("lol", []byte("LOL"))
			})
			file, err := aliceLaptop.LoadFile("lol")
			Expect(err).To(BeNil())
			Expect(string(file)).To(Equal("lolLOL"))
			//userlib.DebugMsg("Bandwidth for AppendToFile: %f", bw)
			contentRandomBig := make([]byte, 10000000)
			contenRandomMid := make([]byte, 100000)

			bw2 := measureBandwidth(func() {
				aliceDesktop.AppendToFile("lol", contentRandomBig)
			})
			//userlib.DebugMsg("Bandwidth for AppendToFile: %f", bw2)

			bw3 := measureBandwidth(func() {
				aliceLaptop.AppendToFile("lol", contenRandomMid)
			})
			userlib.DebugMsg("Bandwidth for AppendToFile: %f", bw3)
			Expect(bw3).To(BeNumerically(">", bw))
			Expect(bw3).To(BeNumerically("<", bw2))
			Expect(bw2 / bw3).To(BeNumerically("<=", 100))

		})
	})
	Describe("Fuzz User", func() {
		Specify("Fuzz User: hex for username, 0 for password", func() {
			_, err := client.InitUser("\x06", "0")
			Expect(err).To(BeNil())

			_, err = client.GetUser("\x06", "0")
			Expect(err).To(BeNil())
		})
		Specify("Fuzz User: hex for username, normal password", func() {
			_, err := client.InitUser("\x06", "jkl")
			Expect(err).To(BeNil())

			_, err = client.GetUser("\x06", "jkl")
			Expect(err).To(BeNil())

		})
		Specify("Fuzz User: letter username, 0 for password", func() {
			_, err := client.InitUser("alice", "0")
			Expect(err).To(BeNil())

			_, err = client.GetUser("alice", "0")
			Expect(err).To(BeNil())

		})
		Specify("Fuzz User: Space, Tab, No Space", func() {
			_, err = client.InitUser("122e4ABCDEabcdeh", "122e4ABCDEabcdeNO SPACE")
			Expect(err).To(BeNil())
			_, err = client.InitUser("122e4ABCD	Eabcdeh", "122e4ABCDEabcdeTab")
			Expect(err).To(BeNil())
			_, err = client.InitUser("122e4ABCD Eabcdeh", "122e4ABCDEabcdeSPACE")
			Expect(err).To(BeNil())
			_, err = client.InitUser("122e4ABCD		Eabcdeh", "122e4ABCDEabcdetabtab")
			Expect(err).To(BeNil())

			_, err = client.GetUser("122e4ABCDEabcdeh", "122e4ABCDEabcdeNO SPACE")
			Expect(err).To(BeNil())
			_, err = client.GetUser("122e4ABCD	Eabcdeh", "122e4ABCDEabcdeTab")
		})
		/*			Expect(err).ToNot(BeNil())
					_, err = client.GetUser("122e4ABCD	Eabcdeh", "122e4ABCDEabcdeSPACE")
					userlib.DebugMsg("err: %v", err)
					Expect(err).To(BeNil())

					_, err = client.GetUser("122e4ABCD		Eabcdeh", "122e4ABCDEabcdetabtab")
					Expect(err).To(BeNil())
					_, err = client.GetUser("122e4ABCD		Eabcdeh", "122e4ABCDEabcdetab")
					Expect(err).ToNot(BeNil())

				})*/
		Specify("Fuzz User: Special Characters", func() {
			_, err = client.InitUser("abcder4daa哈哈哈😂da\x00ADADDd", " ")
			Expect(err).To(BeNil())
			_, err = client.InitUser("abcder4 daa哈哈哈😂da\x00ADADDd", " ")
			Expect(err).To(BeNil())
			_, err = client.InitUser("abcder4 d\x00aa哈哈哈😂da\x00ADADDd", " ")
			Expect(err).To(BeNil())
			_, err = client.InitUser("abcADVCDAcdef13！！#(_#%_051012349【uqejipwFKDml;/sAC《X >Zad00001kadl9478", "12")
			Expect(err).To(BeNil())

			_, err = client.GetUser("abcder4daa哈哈哈😂da\x00ADADDd", " ")
			Expect(err).To(BeNil())
			_, err = client.GetUser("abcADVCDAcdef13！！#(_#%_051012349【uqejipwFKDml;/sAC《X >Zad00001kadl9478", "12")
			Expect(err).To(BeNil())

		})
		Specify("Fuzz User: Failed1", func() {
			_, err = client.InitUser("\xae", "0")
			Expect(err).To(BeNil())
			_, err = client.GetUser("\xae", "0")
			Expect(err).To(BeNil())
		})

	})
	Describe("Single User: Fuzz File", func() {
		Specify("Easy: File Name Contains Hex", func() {
			alice, err := client.InitUser("alice\x90\x00lol", "jkl")
			Expect(err).To(BeNil())

			err = alice.StoreFile("lol]x\x978\x89\x9AAAAAAAA", []byte("lol\x90\x00lol"))
			Expect(err).To(BeNil())

			err = alice.AppendToFile("lol]x\x978\x89\x9AAAAAAAA", []byte("lol"))
			Expect(err).To(BeNil())

			data, err := alice.LoadFile("lol]x\x978\x89\x9AAAAAAAA")
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte("lol\x90\x00lollol")))

			err = alice.StoreFile("lol]x\x978\x89\x9AAAAAAAA", []byte("lol\x90"))
			Expect(err).To(BeNil())

			data, err = alice.LoadFile("lol]x\x978\x89\x9AAAAAAAA")
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte("lol\x90")))

		})
		Specify("Easy: File Name 0", func() {
			alice, err := client.InitUser("t", "0")
			Expect(err).To(BeNil())

			err = alice.StoreFile("0", []byte("0"))
			Expect(err).To(BeNil())
		})
	})
	Describe("Advanced Tests", func() {
		Describe("AppendToFileEfficiency", func() {
			user := "Alice"
			password := "securePassword"
			fileContent := "Initial content"
			filename := "file1.txt"
			appendContent := "Appended content "
			numberOfAppends := 200

			lastBandwidthUsed := 0

			measureBandwidth = func(probe func()) (bandwidth int) {
				before := userlib.DatastoreGetBandwidth()
				probe()
				after := userlib.DatastoreGetBandwidth()
				return after - before
			}
			Context("AppendToFileEfficiency: when appending content multiple times", func() {

				session, _ := client.InitUser(user, password)
				_ = session.StoreFile(filename, []byte(fileContent))

				for i := 0; i < numberOfAppends; i++ {
					bandwidthUsed := measureBandwidth(func() {
						_ = session.AppendToFile(filename, []byte(appendContent))
					})
					fileContent += appendContent
					It(fmt.Sprintf("should use consistent bandwidth for append operation %d", i+1), func() {
						if lastBandwidthUsed != 0 {
							Expect(bandwidthUsed).To(BeNumerically("~", lastBandwidthUsed, 256))
						}
						lastBandwidthUsed = bandwidthUsed
					})
				}
			})
		})
		Describe("Fuzz Tests", func() {
			Specify("Fuzz Test: Random Operations with Users and Files", func() {
				initializedUsers := make(map[string]*client.User)
				for i := 0; i < 100; i++ { // Repeat multiple times to explore various scenarios.
					action := rand.Intn(5)
					fileContent := "Random content " + strconv.Itoa(rand.Intn(1000))
					fileName := "file" + strconv.Itoa(rand.Intn(100))

					username := "user" + strconv.Itoa(rand.Intn(100))
					password := "" // Password can be empty

					user, exists := initializedUsers[username]
					if !exists {
						var err error
						user, err = client.InitUser(username, password)
						if err != nil {
							logFailure(fmt.Sprintf("InitUser failed for username: %s, password: %s", username, password))
							continue
						}
						Expect(err).To(BeNil())
						initializedUsers[username] = user
					}

					switch action {
					case 0:
						err = user.StoreFile(fileName, []byte(fileContent))
						if err != nil {
							logFailure(
								fmt.Sprintf("StoreFile Case 0 failed for username: %s, password: %s, fileName: %s, "+
									"fileContent: %s",
									username, password, fileName, fileContent))
							continue
						}

					case 1:
						invitee := "user" + strconv.Itoa(rand.Intn(100))
						_, err = user.CreateInvitation(fileName, invitee)
						if err != nil {
							logFailure(
								fmt.Sprintf("StoreFile Case 0 failed for username: %s, password: %s, fileName: %s, "+
									"invitee: %s "+
									"fileContent: %s",
									username, password, fileName, invitee, fileContent))
							continue
						}
					case 2:
						inviter := "user" + strconv.Itoa(rand.Intn(100))
						user, exists := initializedUsers[username]
						if !exists {
							var err error
							user, err = client.InitUser(username, password)
							Expect(err).To(BeNil())
							initializedUsers[username] = user
						}
						invite, err1 := user.CreateInvitation(fileName, username)
						if err1 != nil {
							logFailure(
								fmt.Sprintf("StoreFile Case 0 failed for username: %s, password: %s, fileName: %s, "+
									"fileContent: %s",
									username, password, fileName, fileContent))
							continue
						}
						Expect(err1).To(BeNil())
						err = user.AcceptInvitation(inviter, invite, fileName)
						if err != nil {
							logFailure(
								fmt.Sprintf("AcceptInvitation failed for username: %s, password: %s, fileName: %s, "+
									"fileContent: %s, inviter: %s",
									username, password, fileName, fileContent, inviter))
							continue
						}
					case 3:
						appendContent := "Appending " + strconv.Itoa(rand.Intn(100))
						err = user.AppendToFile(fileName, []byte(appendContent))
						if err != nil {
							logFailure(
								fmt.Sprintf("Append failed for username: %s, password: %s, fileName: %s, "+
									"fileContent: %s, appendContent: %s",
									username, password, fileName, fileContent, appendContent))
							continue
						}
					case 4:
						revokee := "user" + strconv.Itoa(rand.Intn(100))
						err = user.RevokeAccess(fileName, revokee)
						if err != nil {
							logFailure(
								fmt.Sprintf("Revoke failed for username: %s, password: %s, fileName: %s, "+
									"Revokee: %s "+
									"fileContent: %s",
									username, password, fileName, revokee, fileContent))
							continue
						}
					}

				}
			})
			Specify("FailedFuzz-User", func() {
				someUser := "\xf8"
				zeroPW := "10"

				_, err := client.InitUser(someUser, zeroPW)
				PWHash := userlib.Argon2Key([]byte(zeroPW), []byte(someUser), 64)
				userid, err := userlib.HashKDF(PWHash[:16],
					[]byte("userid"))
				Expect(err).To(BeNil())
				userUUID, err := uuid.FromBytes(userid[:16])
				Expect(err).To(BeNil())

				userlib.DatastoreGet(userUUID)

				_, err = client.GetUser(someUser, zeroPW)
				Expect(err).To(BeNil())
			})
		})

	})
	Describe("Fuzz Tests", func() {
		Specify("Fuzz Test: Random Operations with Users and Files", func() {
			initializedUsers := make(map[string]*client.User)
			for i := 0; i < 100; i++ { // Repeat multiple times to explore various scenarios.
				action := rand.Intn(5)
				fileContent := "Random content " + strconv.Itoa(rand.Intn(1000))
				fileName := "file" + strconv.Itoa(rand.Intn(100))

				username := "user" + strconv.Itoa(rand.Intn(100))
				password := "" // Password can be empty

				user, exists := initializedUsers[username]
				if !exists {
					var err error
					user, err = client.InitUser(username, password)
					if err != nil {
						logFailure(fmt.Sprintf("InitUser failed for username: %s, password: %s", username, password))
						continue
					}
					Expect(err).To(BeNil())
					initializedUsers[username] = user
				}

				switch action {
				case 0:
					err = user.StoreFile(fileName, []byte(fileContent))
					if err != nil {
						logFailure(
							fmt.Sprintf("StoreFile Case 0 failed for username: %s, password: %s, fileName: %s, "+
								"fileContent: %s",
								username, password, fileName, fileContent))
						continue
					}

				case 1:
					invitee := "user" + strconv.Itoa(rand.Intn(100))
					_, err = user.CreateInvitation(fileName, invitee)
					if err != nil {
						logFailure(
							fmt.Sprintf("StoreFile Case 0 failed for username: %s, password: %s, fileName: %s, "+
								"invitee: %s "+
								"fileContent: %s",
								username, password, fileName, invitee, fileContent))
						continue
					}
				case 2:
					inviter := "user" + strconv.Itoa(rand.Intn(100))
					user, exists := initializedUsers[username]
					if !exists {
						var err error
						user, err = client.InitUser(username, password)
						Expect(err).To(BeNil())
						initializedUsers[username] = user
					}
					invite, err1 := user.CreateInvitation(fileName, username)
					if err1 != nil {
						logFailure(
							fmt.Sprintf("StoreFile Case 0 failed for username: %s, password: %s, fileName: %s, "+
								"fileContent: %s",
								username, password, fileName, fileContent))
						continue
					}
					Expect(err1).To(BeNil())
					err = user.AcceptInvitation(inviter, invite, fileName)
					if err != nil {
						logFailure(
							fmt.Sprintf("AcceptInvitation failed for username: %s, password: %s, fileName: %s, "+
								"fileContent: %s, inviter: %s",
								username, password, fileName, fileContent, inviter))
						continue
					}
				case 3:
					appendContent := "Appending " + strconv.Itoa(rand.Intn(100))
					err = user.AppendToFile(fileName, []byte(appendContent))
					if err != nil {
						logFailure(
							fmt.Sprintf("Append failed for username: %s, password: %s, fileName: %s, "+
								"fileContent: %s, appendContent: %s",
								username, password, fileName, fileContent, appendContent))
						continue
					}
				case 4:
					revokee := "user" + strconv.Itoa(rand.Intn(100))
					err = user.RevokeAccess(fileName, revokee)
					if err != nil {
						logFailure(
							fmt.Sprintf("Revoke failed for username: %s, password: %s, fileName: %s, "+
								"Revokee: %s "+
								"fileContent: %s",
								username, password, fileName, revokee, fileContent))
						continue
					}
				}

			}
		})

		Specify("Fuzz Test: I/O Efficiency", func() {
			session, _ := client.InitUser("EfficiencyUser", "password")

			for i := 0; i < 100; i++ {
				// Create a large file and perform multiple small appends
				filename := "bigFile" + strconv.Itoa(i)
				initialContent := userlib.RandomBytes(1024 * 1024) // 1 MB
				session.StoreFile(filename, initialContent)

				// Append small amounts repeatedly
				for j := 0; j < 100; j++ {
					appendContent := userlib.RandomBytes(100) // 100 B
					session.AppendToFile(filename, appendContent)

					// Read the file and verify the contents
				}
			}
		})

		Specify("Fuzz Test: Sharing and Revocation", func() {
			// Create users and sessions
			aliceSession, _ := client.InitUser("Alice", "password")
			bobSession, _ := client.InitUser("Bob", "password")

			// Share files and test complex sharing trees
			for i := 0; i < 100; i++ {
				// Create and share files
				filename := "file" + strconv.Itoa(i)
				aliceFileContent := userlib.RandomBytes(rand.Intn(1024))
				aliceSession.StoreFile(filename, aliceFileContent)
				invitation, _ := aliceSession.CreateInvitation(filename, "Bob")

				// Bob accepts invitation
				bobSession.AcceptInvitation("Alice", invitation, filename)

				// Alice revokes access
				aliceSession.RevokeAccess(filename, "Bob")

				// Bob tries to access the file
				_, err := bobSession.LoadFile(filename)
				if err == nil {
					logFailure(fmt.Sprintf("Revocation failed for filename: %s", filename))
				}

				// Alice tries to revoke access again
				err = aliceSession.RevokeAccess(filename, "Bob")
				if err == nil {
					logFailure(fmt.Sprintf("Revocation failed for filename: %s", filename))
				}

				// Bob tries to accept invitation again
				err = bobSession.AcceptInvitation("Alice", invitation, filename)
				if err == nil {
					logFailure(fmt.Sprintf("Revocation failed for filename: %s", filename))
				}

				// Alice Load file
				content, err := aliceSession.LoadFile(filename)
				if err != nil {
					logFailure(fmt.Sprintf("LoadFile failed for filename: %s", filename))
				}
				if !bytes.Equal(content, aliceFileContent) {
					logFailure(fmt.Sprintf("LoadFile failed for filename: %s", filename))
				}

			}
		})

	})
	Describe("Basic Tests", func() {

		Specify("Basic Test: Testing InitUser/GetUser on a single user.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user Alice.")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())
		})

		Specify("Basic Test: Testing Single User Store/Load/Append.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appending file data: %s", contentTwo)
			err = alice.AppendToFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appending file data: %s", contentThree)
			err = alice.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Loading file...")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))
		})

		Specify("Basic Test: Testing Create/Accept Invite Functionality with multiple users and multiple instances.", func() {
			userlib.DebugMsg("Initializing users Alice (aliceDesktop) and Bob.")
			aliceDesktop, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			//fmt.Printf("aliceDesktop: %v\n", aliceDesktop)

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting second instance of Alice - aliceLaptop")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceDesktop storing file %s with content: %s", aliceFile, contentOne)
			err = aliceDesktop.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceLaptop creating invite for Bob.")
			invite, err := aliceLaptop.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob accepting invite from Alice under filename %s.", bobFile)
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Bob sees expected file data.")
			data, err := bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Bob appending to file %s, content: %s", bobFile, contentTwo)
			err = bob.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceDesktop appending to file %s, content: %s", aliceFile, contentThree)
			err = aliceDesktop.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that aliceDesktop sees expected file data.")
			data, err = aliceDesktop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Checking that aliceLaptop sees expected file data.")
			data, err = aliceLaptop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Checking that Bob sees expected file data.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Getting third instance of Alice - alicePhone.")
			alicePhone, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that alicePhone sees Alice's changes.")
			data, err = alicePhone.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))
		})

		Specify("Basic Test: Testing Revoke Functionality", func() {
			userlib.DebugMsg("Initializing users Alice, Bob, and Charlie.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			alice.StoreFile(aliceFile, []byte(contentOne))

			userlib.DebugMsg("Alice creating invite for Bob for file %s, and Bob accepting invite under name %s.", aliceFile, bobFile)

			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice can still load the file.")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Bob can load the file.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Bob creating invite for Charles for file %s, and Charlie accepting invite under name %s.", bobFile, charlesFile)
			invite, err = bob.CreateInvitation(bobFile, "charles")
			Expect(err).To(BeNil())

			err = charles.AcceptInvitation("bob", invite, charlesFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Bob can load the file.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Charles can load the file.")
			data, err = charles.LoadFile(charlesFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Alice revoking Bob's access from %s.", aliceFile)
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice can still load the file.")
			data, err = alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Bob/Charles lost access to the file.")
			x, err := bob.LoadFile(bobFile)
			userlib.DebugMsg("Bob's file: %s", x)

			Expect(err).ToNot(BeNil())

			_, err = charles.LoadFile(charlesFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Checking that the revoked users cannot append to the file.")
			err = bob.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())

			err = charles.AppendToFile(charlesFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())
		})

	})
	Describe("Sharing With Multiple Person", func() {
		Specify("Basic Test: Sharing with Multiple People", func() {
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())
			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())
			david, err = client.InitUser("david", defaultPassword)
			Expect(err).To(BeNil())
			aliceDesktop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			alicePhone, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			bobDesktop, err = client.GetUser("bob", defaultPassword)
			Expect(err).To(BeNil())
			bobLaptop, err = client.GetUser("bob", defaultPassword)
			Expect(err).To(BeNil())
			bobPhone, err = client.GetUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			contentRandomLong := []byte(strings.Repeat("This is a random long string that is longer than 16 bytes.", 1<<20))
			contentRandomShort := []byte(strings.Repeat("This is a random short string.", 1<<10))

			err = alice.StoreFile("aliceFile1", contentRandomLong)
			Expect(err).To(BeNil())
			err = alice.StoreFile("aliceFile2", contentRandomLong)
			Expect(err).To(BeNil())
			err = alice.StoreFile("aliceFile3", contentRandomShort)
			Expect(err).To(BeNil())

			invite, err := alice.CreateInvitation("aliceFile1", "bob")
			Expect(err).To(BeNil())
			err = alice.RevokeAccess("aliceFile1", "bob")
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation("alice", invite, "bobFile1")
			_, err = bob.LoadFile("bobFile1")
			Expect(err).ToNot(BeNil())
			err = bob.AppendToFile("bobFile1", contentRandomShort)
			Expect(err).ToNot(BeNil())
			err = bob.StoreFile("bobFile1", contentRandomShort)
			Expect(err).To(BeNil())
			content, err := bob.LoadFile("bobFile1")
			Expect(err).To(BeNil())
			Expect(content).To(Equal(contentRandomShort))

			invite, err = alice.CreateInvitation("aliceFile2", "bob")
			Expect(err).To(BeNil())
			err = bob.AcceptInvitation("alice", invite, "bobFile2")
			Expect(err).To(BeNil())

			invite, err = alice.CreateInvitation("aliceFile2", "charles")
			Expect(err).To(BeNil())
			err = charles.AcceptInvitation("alice", invite, "charlesFile2")
			Expect(err).To(BeNil())

			invite, err = alice.CreateInvitation("aliceFile2", "david")
			Expect(err).To(BeNil())
			err = david.AcceptInvitation("alice", invite, "davidFile2")
			Expect(err).To(BeNil())

			content, err = bob.LoadFile("bobFile2")
			Expect(err).To(BeNil())
			Expect(content).To(Equal(contentRandomLong))

			content, err = charles.LoadFile("charlesFile2")
			Expect(err).To(BeNil())
			Expect(content).To(Equal(contentRandomLong))

			content, err = david.LoadFile("davidFile2")
			Expect(err).To(BeNil())
			Expect(content).To(Equal(contentRandomLong))

			err = bob.AppendToFile("bobFile2", contentRandomShort)
			Expect(err).To(BeNil())

			content, err = bobLaptop.LoadFile("bobFile2")
			Expect(err).To(BeNil())
			Expect(content).To(Equal(append(contentRandomLong, contentRandomShort...)))

			content, err = bobDesktop.LoadFile("bobFile2")
			Expect(err).To(BeNil())
			Expect(content).To(Equal(append(contentRandomLong, contentRandomShort...)))

			content, err = bobPhone.LoadFile("bobFile2")
			Expect(err).To(BeNil())
			Expect(content).To(Equal(append(contentRandomLong, contentRandomShort...)))

			err = alice.RevokeAccess("aliceFile2", "bob")
			Expect(err).To(BeNil())

			err = aliceDesktop.RevokeAccess("aliceFile2", "charles")
			Expect(err).To(BeNil())

			_, err = charles.LoadFile("charlesFile2")
			Expect(err).ToNot(BeNil())
			err = aliceLaptop.StoreFile("aliceFile2", contentRandomShort)
			Expect(err).To(BeNil())
			content, err = david.LoadFile("davidFile2")
			Expect(err).To(BeNil())
			Expect(content).To(Equal(contentRandomShort))

		})

	})
	Describe("Advanced Fuzz Testing: Further Deep Dive", func() {

		Describe("Further Advanced Test Cases", func() {

			It("should handle multiple rounds of sharing and revoking", func() {
				owner, _ := client.InitUser("multi_share_owner", "password")
				recipient1, _ := client.InitUser("multi_share_recipient1", "password")
				recipient2, _ := client.InitUser("multi_share_recipient2", "password")

				filename := "multi_share_file"
				content := []byte("multi share content")
				err := owner.StoreFile(filename, content)
				Expect(err).To(BeNil())

				// Round 1: Share with recipient1
				invitation1, err := owner.CreateInvitation(filename, "multi_share_recipient1")
				Expect(err).To(BeNil())

				err = recipient1.AcceptInvitation("multi_share_owner", invitation1, filename)
				Expect(err).To(BeNil())

				// Round 2: Share with recipient2 using recipient1's credentials
				invitation2, err := recipient1.CreateInvitation(filename, "multi_share_recipient2")
				Expect(err).To(BeNil())

				err = recipient2.AcceptInvitation("multi_share_recipient1", invitation2, filename)
				Expect(err).To(BeNil())

				// Revoke access from recipient1
				err = owner.RevokeAccess(filename, "multi_share_recipient1")
				Expect(err).To(BeNil())

				// Recipient2 should also lose access due to propagation of revoke
				_, err = recipient2.LoadFile(filename)
				Expect(err).NotTo(BeNil()) // Error should be raised since access should be revoked

			})

			It("should check behavior for deleted users' credentials", func() {
				user, _ := client.InitUser("deleted_user", "password")
				filename := "deleted_file"
				content := []byte("deleted content")
				err := user.StoreFile(filename, content)
				Expect(err).To(BeNil())

				// Directly delete user's data from datastore to simulate deletion
				datastoreMap := userlib.DatastoreGetMap()
				for k := range datastoreMap {
					userlib.DatastoreDelete(k)
				}

				_, err = client.GetUser("deleted_user", "password")
				Expect(err).NotTo(BeNil()) // Error should be raised as user data is deleted

			})

			It("should handle tampering with potential internal mechanisms", func() {
				user, _ := client.InitUser("internal_user", "password")
				filename := "internal_file"
				content := []byte("internal content")
				err := user.StoreFile(filename, content)
				Expect(err).To(BeNil())

				// Tamper with the datastore to simulate an attacker modifying potential cryptographic signatures
				datastoreMap := userlib.DatastoreGetMap()
				for k := range datastoreMap {
					datastoreMap[k] = append(datastoreMap[k], []byte("fake_signature")...)
				}

				_, err = user.LoadFile(filename)
				Expect(err).NotTo(BeNil()) // Error should be raised due to tampering

				// Additional tests can involve:
				// - Tampering with various other potential internal mechanisms
				// - Trying to manipulate encrypted content, keys, etc.

			})

		})

	})
	Describe("Create, Share, and Revoke", func() {
		alice, err = client.InitUser("alice", defaultPassword)
		Expect(err).To(BeNil())
		bob, err = client.InitUser("bob", defaultPassword)
		Expect(err).To(BeNil())
		bobLaptop, err = client.GetUser("bob", defaultPassword)
		Expect(err).To(BeNil())
		bobPhone, err = client.GetUser("bob", defaultPassword)
		Expect(err).To(BeNil())
		bobDesktop, err = client.GetUser("bob", defaultPassword)
		Expect(err).To(BeNil())
		charles, err = client.InitUser("charles", defaultPassword)
		Expect(err).To(BeNil())
		david, err = client.InitUser("david", defaultPassword)
		Expect(err).To(BeNil())
		doris, err = client.InitUser("doris", defaultPassword)
		Expect(err).To(BeNil())
		var passwordOne = "passwordOne"
		var passwordTwo = "passwordTwo"
		var passwordThree = "passwordThree"
		var passwordFour = "passwordFour"

		eve, err = client.InitUser("eve", passwordOne)
		Expect(err).To(BeNil())
		frank, err = client.InitUser("frank", passwordTwo)
		Expect(err).To(BeNil())
		grace, err = client.InitUser("grace", passwordThree)
		Expect(err).To(BeNil())
		horace, err = client.InitUser("horace", passwordFour)
		Expect(err).To(BeNil())
		ira, err = client.InitUser("ira", "")
		Expect(err).To(BeNil())

		content := []byte("Some content")
		err = alice.StoreFile("aliceFile", content)
		Expect(err).To(BeNil())

		err = bob.StoreFile("bobFileNotFromAlice", content)

		invite, err := alice.CreateInvitation("aliceFile", "bob")
		Expect(err).To(BeNil())

		err = bob.AcceptInvitation("alice", invite, "bobFile")
		Expect(err).To(BeNil())

		contentB, err := bob.LoadFile("bobFile")
		Expect(err).To(BeNil())
		Expect(contentB).To(Equal(content))

		err = doris.AcceptInvitation("alice", invite, "dorisFile")
		Expect(err).ToNot(BeNil()) // This operation should fail

		err = alice.RevokeAccess("aliceFile", "bob")
		Expect(err).To(BeNil())
		contentB, err = bob.LoadFile("bobFile")
		Expect(err).ToNot(BeNil()) // This operation should fail
		err = bob.AppendToFile("bobFile", []byte("Some more content"))
		Expect(err).ToNot(BeNil()) // This operation should fail

		contentBN, err := bobLaptop.LoadFile("bobFileNotFromAlice")
		Expect(err).To(BeNil())
		Expect(contentBN).To(Equal(content))

		err = bobLaptop.AppendToFile("bobFileNotFromAlice", []byte("Some more content"))
		Expect(err).To(BeNil())
		contentBN, err = bobDesktop.LoadFile("bobFileNotFromAlice")
		Expect(err).To(BeNil())
		Expect(contentBN).To(Equal(append(content, []byte("Some more content")...)))

		invite, err = alice.CreateInvitation("aliceFile", "charles")
		Expect(err).To(BeNil())
		err = charles.AcceptInvitation("alice", invite, "charlesFile")
		Expect(err).To(BeNil())
		invite, err = alice.CreateInvitation("aliceFile", "david")
		Expect(err).To(BeNil())
		err = david.AcceptInvitation("alice", invite, "davidFile")
		Expect(err).To(BeNil())
		invite, err = alice.CreateInvitation("aliceFile", "doris")
		Expect(err).To(BeNil())
		err = doris.AcceptInvitation("alice", invite, "dorisFile")
		Expect(err).To(BeNil())

		invite, err = charles.CreateInvitation("charlesFile", "eve")
		Expect(err).To(BeNil())
		err = eve.AcceptInvitation("charles", invite, "eveFile")
		Expect(err).To(BeNil())
		userlib.DebugMsg("I passed Here")

		invite, err = charles.CreateInvitation("charlesFile", "frank")
		Expect(err).To(BeNil())
		err = frank.AcceptInvitation("charles", invite, "frankFile")
		Expect(err).To(BeNil())
		invite, err = eve.CreateInvitation("eveFile", "grace")
		Expect(err).To(BeNil())
		err = grace.AcceptInvitation("eve", invite, "graceFile")
		Expect(err).To(BeNil())
		invite, err = grace.CreateInvitation("graceFile", "horace")
		Expect(err).To(BeNil())
		err = horace.AcceptInvitation("grace", invite, "horaceFile")
		Expect(err).To(BeNil())
		err = grace.AppendToFile("graceFile", []byte(graceFile))
		Expect(err).To(BeNil())
		err = horace.AppendToFile("horaceFile", []byte(horaceFile))
		Expect(err).To(BeNil())
		err = frank.AppendToFile("frankFile", []byte(frankFile))

		contentNow, err := alice.LoadFile("aliceFile")
		Expect(err).To(BeNil())
		Expect(contentNow).To(Equal(append(append(append(content, []byte(graceFile)...), []byte(horaceFile)...),
			[]byte(frankFile)...)))
		contentNow2, err := charles.LoadFile("charlesFile")
		Expect(err).To(BeNil())
		Expect(contentNow2).To(Equal(append(append(append(content, []byte(graceFile)...), []byte(horaceFile)...),
			[]byte(frankFile)...)))

		invite, err = grace.CreateInvitation("graceFile", "ira")
		Expect(err).To(BeNil())
		err = ira.AcceptInvitation("grace", invite, "iraFile")
		Expect(err).To(BeNil())
		userlib.DebugMsg("I passed Here 1")

		err = ira.StoreFile("iraFile", []byte(iraFile))
		Expect(err).To(BeNil())
		userlib.DebugMsg("I passed Here 2")
		contentNow, err = alice.LoadFile("aliceFile")
		Expect(err).To(BeNil())
		userlib.DebugMsg("I passed Here 2")
		userlib.DebugMsg(string(contentNow))
		Expect(contentNow).To(Equal([]byte(iraFile)))
		userlib.DebugMsg("I passed Here 2")

		err = alice.RevokeAccess("aliceFile", "charles")
		Expect(err).To(BeNil())
		contentNow, err = alice.LoadFile("aliceFile")
		Expect(err).To(BeNil())
		Expect(contentNow).To(Equal([]byte(iraFile)))

		_, err = ira.LoadFile("iraFile")
		Expect(err).ToNot(BeNil())
		invite, err = charles.CreateInvitation("charlesFile", "frank")
		Expect(err).ToNot(BeNil())
		err = frank.AcceptInvitation("charles", invite, "frankFile")
		Expect(err).ToNot(BeNil())
		invite, err = eve.CreateInvitation("eveFile", "grace")
		Expect(err).ToNot(BeNil())
		err = grace.AcceptInvitation("eve", invite, "graceFile")
		Expect(err).ToNot(BeNil())
		invite, err = grace.CreateInvitation("graceFile", "horace")
		Expect(err).ToNot(BeNil())
		err = horace.AcceptInvitation("grace", invite, "horaceFile")
		Expect(err).ToNot(BeNil())
		err = grace.AppendToFile("graceFile", []byte(graceFile))
		Expect(err).ToNot(BeNil())
		err = horace.AppendToFile("horaceFile", []byte(horaceFile))
		Expect(err).ToNot(BeNil())
		err = frank.AppendToFile("frankFile", []byte(frankFile))
	})
	Describe("Datastore Adversary Tests", func() {

		It("should detect unauthorized modifications in the datastore", func() {
			alice, err := client.InitUser("alice", "password")
			Expect(alice).NotTo(BeNil())

			// Store a file with known content
			filename := "file.txt"
			content := "This is a test content"
			err = alice.StoreFile(filename, []byte(content))
			Expect(err).To(BeNil())

			// Directly modify the datastore content to simulate adversary's action
			keys := userlib.DatastoreGetMap()
			for key, _ := range keys {
				_, ok := userlib.DatastoreGet(key)
				if ok {
					modifiedData := []byte("malicious data")
					userlib.DatastoreSet(key, modifiedData)
				}
			}

			// Attempt to retrieve the file
			retrievedContent, err := alice.LoadFile(filename)

			// Check if the retrieved content is not equal to the original content, indicating unauthorized modification
			Expect(retrievedContent).NotTo(Equal(content))
		})

	})
	Describe("Multi-User Interaction Tests", func() {

		It("should handle complex sharing and revocation scenarios", func() {
			alice, err := client.InitUser("alice", "alice_password")
			Expect(err).To(BeNil())

			bob, err := client.InitUser("bob", "bob_password")
			Expect(err).To(BeNil())

			charles, err := client.InitUser("charles", "charles_password")
			Expect(err).To(BeNil())

			// Alice stores a file named fileA
			fileA := "fileA"
			contentA := []byte("This is Alice's content")
			err = alice.StoreFile(fileA, contentA)
			Expect(err).To(BeNil())

			// Alice shares fileA with Bob
			inviteForBob, err := alice.CreateInvitation(fileA, "bob")
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation("alice", inviteForBob, fileA)
			Expect(err).To(BeNil())

			// Bob appends content to fileA
			appendContent := []byte(" This is Bob's appended content")
			err = bob.AppendToFile(fileA, appendContent)
			Expect(err).To(BeNil())

			// Bob shares the updated fileA with Charles
			inviteForCharles, err := bob.CreateInvitation(fileA, "charles")
			Expect(err).To(BeNil())

			err = charles.AcceptInvitation("bob", inviteForCharles, fileA)
			Expect(err).To(BeNil())

			// Charles stores a new file named fileC
			fileC := "fileC"
			contentC := []byte("This is Charles's content")
			err = charles.StoreFile(fileC, contentC)
			Expect(err).To(BeNil())

			// Charles shares fileC with both Alice and Bob
			inviteForAlice, err := charles.CreateInvitation(fileC, "alice")
			Expect(err).To(BeNil())

			err = alice.AcceptInvitation("charles", inviteForAlice, fileC)

			Expect(err).To(BeNil())

			inviteForBobFromCharles, err := charles.CreateInvitation(fileC, "bob")
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation("charles", inviteForBobFromCharles, fileC)
			Expect(err).To(BeNil())

			// Alice revokes Bob's access to fileA
			err = alice.RevokeAccess(fileA, "bob")
			Expect(err).To(BeNil())

			// Verification
			// Bob can no longer access fileA
			_, err = bob.LoadFile(fileA)
			Expect(err).NotTo(BeNil())

			// Charles can still access fileA
			_, err = charles.LoadFile(fileA)
			Expect(err).NotTo(BeNil())

			// Both Alice and Bob can access fileC
			aliceContentC, err := alice.LoadFile(fileC)
			Expect(err).To(BeNil())
			Expect(aliceContentC).To(Equal(contentC))

			bobContentC, err := bob.LoadFile(fileC)
			Expect(err).To(BeNil())
			Expect(bobContentC).To(Equal(contentC))
		})
	})
	Describe("User Sessions Tests", func() {

		It("should reflect changes across multiple active sessions for a single user", func() {
			// Initializing Alice on a "laptop"
			aliceLaptop, err := client.InitUser("alice", "alice_password")
			Expect(err).To(BeNil())

			// Initializing Alice on a "tablet"
			aliceTablet, err := client.GetUser("alice", "alice_password")
			Expect(err).To(BeNil())

			// Alice stores a file from her laptop
			fileA := "sessionTestFile"
			contentA := []byte("Content from Alice's laptop")
			err = aliceLaptop.StoreFile(fileA, contentA)
			Expect(err).To(BeNil())

			// Alice tries to load the file from her tablet
			loadedContent, err := aliceTablet.LoadFile(fileA)
			Expect(err).To(BeNil())
			Expect(loadedContent).To(Equal(contentA))

			// Alice appends content from her tablet
			appendContent := []byte(" Appended from Alice's tablet")
			err = aliceTablet.AppendToFile(fileA, appendContent)
			Expect(err).To(BeNil())

			// Alice tries to load the updated content from her laptop
			updatedContent, err := aliceLaptop.LoadFile(fileA)
			Expect(err).To(BeNil())
			Expect(updatedContent).To(Equal(append(contentA, appendContent...)))
		})

	})
	Describe("Cryptography and Key Constraints Tests", func() {

		It("should ensure confidentiality of file content", func() {
			alice, err := client.InitUser("alice", "alice_password")
			Expect(err).To(BeNil())

			// Alice stores a file
			fileA := "cryptoTestFile"
			contentA := []byte("Confidential content by Alice")
			err = alice.StoreFile(fileA, contentA)
			Expect(err).To(BeNil())

			// Adversary attempts to fetch the content directly from datastore
			// Without knowing the exact key, this test will be a little abstracted.
			// We'll fetch all the keys from datastore and ensure none of them contains contentA as plain text.
			allData := userlib.DatastoreGetMap() // This is an abstract function, assumed to fetch all datastore content
			for _, data := range allData {
				Expect(string(data)).NotTo(ContainSubstring(string(contentA)))
			}
		})

		It("should ensure integrity of file contents", func() {
			alice, err := client.InitUser("alice", "alice_password")
			Expect(err).To(BeNil())

			// Alice stores a file
			fileB := "integrityTestFile"
			contentB := []byte("Original content by Alice")
			err = alice.StoreFile(fileB, contentB)
			Expect(err).To(BeNil())

			// Malicious adversary modifies the file content directly in the datastore
			// Without knowing the exact key, this test will be a bit abstracted.
			// We'll modify a random entry in the datastore to emulate unauthorized changes.
			randomKey, err := uuid.NewRandom()
			userlib.DatastoreSet(randomKey, []byte("Malicious modification"))

			// Alice tries to load the file
			loadedContent, err := alice.LoadFile(fileB)
			Expect(err).To(BeNil())
			Expect(loadedContent).To(Equal(contentB)) // Content should remain unchanged despite the malicious attempt
		})

	})
	Describe("No Persistent Local State Tests", func() {

		It("should be able to retrieve stored data after client restart using only username and password", func() {
			alice, err := client.InitUser("alice", "alice_password")
			Expect(err).To(BeNil())

			// Alice stores a file
			fileA := "restartTestFile"
			contentA := []byte("Content before client restart")
			err = alice.StoreFile(fileA, contentA)
			Expect(err).To(BeNil())

			// Simulate a client restart by reinitializing Alice
			aliceRestarted, err := client.GetUser("alice", "alice_password")
			Expect(err).To(BeNil())

			// Alice tries to load the file after client restart
			loadedContent, err := aliceRestarted.LoadFile(fileA)
			Expect(err).To(BeNil())
			Expect(loadedContent).To(Equal(contentA))
		})

	})
	Describe("File Constraints Tests", func() {

		It("should handle file with a filename of length zero", func() {
			alice, err := client.InitUser("alice", "alice_password")
			Expect(err).To(BeNil())

			// Alice stores a file with a filename of length zero
			fileA := ""
			contentA := []byte("Content for file with empty filename")
			err = alice.StoreFile(fileA, contentA)
			Expect(err).To(BeNil())

			// Alice tries to load the file with an empty filename
			loadedContent, err := alice.LoadFile(fileA)
			Expect(err).To(BeNil())
			Expect(loadedContent).To(Equal(contentA))
		})
		It("should ensure integrity of filenames", func() {
			bob, err := client.InitUser("bob", "bob_password")
			Expect(err).To(BeNil())

			// Bob stores a file
			fileB := "integrityFilenameTestFile"
			contentB := []byte("Content by Bob")
			err = bob.StoreFile(fileB, contentB)
			Expect(err).To(BeNil())

			// Simulate an adversary's attempt to add unrelated data to the datastore
			randomKey, err := uuid.NewRandom()
			userlib.DatastoreSet(randomKey, []byte("Unrelated data"))

			// Bob tries to load the file
			loadedContent, err := bob.LoadFile(fileB)
			Expect(err).To(BeNil())
			Expect(loadedContent).To(Equal(contentB))
		})

	})
	Describe("Sharing and Revocation Tests", func() {

		It("should allow a user to share a file and the recipient to access it", func() {
			alice, err := client.InitUser("alice", "alice_password")
			Expect(err).To(BeNil())

			bob, err := client.InitUser("bob", "bob_password")
			Expect(err).To(BeNil())

			// Alice stores a file
			fileA := "shareTestFile"
			contentA := []byte("Content to be shared with Bob")
			err = alice.StoreFile(fileA, contentA)
			Expect(err).To(BeNil())

			// Alice shares the file with Bob
			invitationPtr, err := alice.CreateInvitation(fileA, "bob")
			Expect(err).To(BeNil())

			// Bob accepts the invitation
			err = bob.AcceptInvitation("alice", invitationPtr, fileA)
			Expect(err).To(BeNil())

			// Bob tries to load the shared file
			loadedContent, err := bob.LoadFile(fileA)
			Expect(err).To(BeNil())
			Expect(loadedContent).To(Equal(contentA))
		})

		It("should revoke access to a file and prevent the revoked user from accessing it", func() {
			alice, err := client.InitUser("alice", "alice_password")
			Expect(err).To(BeNil())

			bob, err := client.InitUser("bob", "bob_password")
			Expect(err).To(BeNil())

			// Alice stores a file
			fileB := "revokeTestFile"
			contentB := []byte("Content to be revoked from Bob")
			err = alice.StoreFile(fileB, contentB)
			Expect(err).To(BeNil())

			// Alice shares the file with Bob
			invitationPtr, err := alice.CreateInvitation(fileB, "bob")
			Expect(err).To(BeNil())

			// Bob accepts the invitation
			err = bob.AcceptInvitation("alice", invitationPtr, fileB)
			Expect(err).To(BeNil())

			// Alice revokes Bob's access
			err = alice.RevokeAccess(fileB, "bob")
			Expect(err).To(BeNil())

			// Bob tries to load the file after revocation
			_, err = bob.LoadFile(fileB)
			Expect(err).NotTo(BeNil()) // Error should occur since Bob's access was revoked
		})

	})
	Describe("Revoked User Adversary Tests", func() {

		It("should prevent a revoked user from accessing the file after revocation", func() {
			alice, err := client.InitUser("alice", "alice_password")
			Expect(err).To(BeNil())

			bob, err := client.InitUser("bob", "bob_password")
			Expect(err).To(BeNil())

			// Alice stores a file
			fileA := "revokeAdversaryTestFile"
			contentA := []byte("Content for revoked user adversary test")
			err = alice.StoreFile(fileA, contentA)
			Expect(err).To(BeNil())

			// Alice shares the file with Bob
			invitationPtr, err := alice.CreateInvitation(fileA, "bob")
			Expect(err).To(BeNil())

			err = alice.RevokeAccess(fileA, "bob")

			// Bob accepts the invitation
			err = bob.AcceptInvitation("alice", invitationPtr, fileA)
			Expect(err).ToNot(BeNil())

			// Bob turns malicious and tries to load the file
			_, err = bob.LoadFile(fileA)
			Expect(err).NotTo(BeNil()) // Bob should receive an error

			// Bob tries to append to the file
			err = bob.AppendToFile(fileA, []byte("Malicious append attempt"))
			Expect(err).NotTo(BeNil()) // Bob should receive an error
		})

	})
	Describe("Fuzz Testing", func() {

		// Extreme Inputs
		Describe("Extreme Inputs", func() {
			It("should handle extremely long usernames", func() {
				longUsername := strings.Repeat("a", 1e6) // 1 million characters
				_, err := client.InitUser(longUsername, "password")
				Expect(err).To(BeNil())
			})

			It("should handle very short usernames", func() {
				_, err := client.InitUser("a", "password")
				Expect(err).To(BeNil())
			})

			It("should handle very long passwords", func() {
				longPassword := strings.Repeat("a", 1e6) // 1 million characters
				_, err := client.InitUser("username", longPassword)
				Expect(err).To(BeNil())
			})

			It("should handle empty password", func() {
				_, err := client.InitUser("username", "")
				Expect(err).To(BeNil())
			})

			It("should handle extremely large files", func() {
				user, _ := client.InitUser("username", "password")
				largeContent := strings.Repeat("a", 1e6) // 1 million characters
				err := user.StoreFile("filename", []byte(largeContent))
				Expect(err).To(BeNil())
			})
		})

		// Repeated Operations
		Describe("Repeated Operations", func() {
			It("should handle repeated store operations", func() {
				user, _ := client.InitUser("username", "password")
				for i := 0; i < 1e2; i++ {
					err := user.StoreFile(fmt.Sprintf("filename_%d", i), []byte("content"))
					Expect(err).To(BeNil())
				}
			})

			It("should handle repeated load operations", func() {
				user, _ := client.InitUser("username", "password")
				user.StoreFile("filename", []byte("content"))
				for i := 0; i < 1e2; i++ {
					_, err := user.LoadFile("filename")
					Expect(err).To(BeNil())
				}
			})

			It("should handle repeated appends", func() {
				user, _ := client.InitUser("username", "password")
				user.StoreFile("filename", []byte("content"))
				for i := 0; i < 1e2; i++ {
					err := user.AppendToFile("filename", []byte(fmt.Sprintf("_append_%d", i)))
					Expect(err).To(BeNil())
				}
			})
		})
	})
	Describe("RevisedSecurityTests", func() {

		Context("Integrity Checks", func() {

			It("Should detect tampering in Datastore", func() {
				// Initialization of user and store some data
				user, _ := client.InitUser("Alice", "password")
				user.StoreFile("file1", []byte("This is a secret content"))

				// Tamper with the data in the datastore
				for UUID, data := range userlib.DatastoreGetMap() {
					tamperedData := append(data, []byte("tamper")...)
					userlib.DatastoreSet(UUID, tamperedData)
				}

				// Attempt to retrieve the tampered data
				_, err := user.LoadFile("file1")
				Expect(err).To(HaveOccurred()) // Expect an error since the data was tampered
			})

		})

		Context("Authorization and Access Control", func() {

			It("Should not allow unauthorized file retrieval", func() {
				// Initialization of two users
				alice, _ := client.InitUser("Alice", "password1")
				bob, _ := client.InitUser("Bob", "password2")
				alice.StoreFile("file1", []byte("Alice's secret content"))

				// Bob tries to retrieve Alice's file without proper authorization
				_, err := bob.LoadFile("file1")
				Expect(err).To(HaveOccurred()) // Expect an error since Bob is not authorized
			})

			It("Should enforce revocation", func() {
				alice, _ := client.InitUser("Alice", "password1")
				bob, _ := client.InitUser("Bob", "password2")
				alice.StoreFile("file1", []byte("Content"))
				invite, _ := alice.CreateInvitation("file1", "Bob")
				bob.AcceptInvitation("Alice", invite, "file1_shared")

				// Alice revokes Bob's access
				alice.RevokeAccess("file1", "Bob")

				// Bob tries to retrieve the file after revocation
				_, err := bob.LoadFile("file1_shared")
				Expect(err).To(HaveOccurred()) // Expect an error since Bob's access was revoked
			})

		})

	})
	Describe("Key Reuse", func() {
		It("should have different keys for different filenames by the same user", func() {
			username := "Alice"
			password := "password123"
			filename1 := "file1"
			filename2 := "file2"
			content := []byte("Some content")

			user, _ := client.InitUser(username, password)
			user.StoreFile(filename1, content)

			// Store another file with different filename
			user.StoreFile(filename2, content)

			// Check that the storage keys are different
			storageKey1 := hex.EncodeToString(userlib.Hash([]byte(filename1 + username))[:16])
			storageKey2 := hex.EncodeToString(userlib.Hash([]byte(filename2 + username))[:16])

			Expect(storageKey1).ToNot(Equal(storageKey2))
		})

		It("should have different keys for same filenames by different users", func() {
			username1 := "Alice"
			password1 := "password123"
			username2 := "Bob"
			password2 := "password456"
			filename := "shared_file_name"
			content := []byte("Shared content")

			alice, _ := client.InitUser(username1, password1)
			bob, _ := client.InitUser(username2, password2)

			alice.StoreFile(filename, content)
			bob.StoreFile(filename, content)

			// Check that the storage keys are different
			storageKeyAlice := hex.EncodeToString(userlib.Hash([]byte(filename + username1))[:16])
			storageKeyBob := hex.EncodeToString(userlib.Hash([]byte(filename + username2))[:16])

			Expect(storageKeyAlice).ToNot(Equal(storageKeyBob))
		})

		It("should not reuse keys when the same user stores the same file at different times", func() {
			username := "Alice"
			password := "password123"
			filename := "file1"
			content := []byte("Some content")

			user, _ := client.InitUser(username, password)
			user.StoreFile(filename, content)

			storageKey1 := hex.EncodeToString(userlib.Hash([]byte(filename + username))[:16])

			// Pretend some time has passed and store again
			user.StoreFile(filename, content)

			storageKey2 := hex.EncodeToString(userlib.Hash([]byte(filename + username))[:16])

			Expect(storageKey1).To(Equal(storageKey2)) // The keys should remain consistent for the same user and filename
		})

		It("should not reuse keys across different operations", func() {
			username1 := "Alice"
			password1 := "password123"
			filename1 := "file1"
			content1 := []byte("Hello Alice")

			username2 := "Bob"
			password2 := "password456"
			filename2 := "file2"
			content2 := []byte("Hello Bob")

			alice, _ := client.InitUser(username1, password1)
			bob, _ := client.InitUser(username2, password2)

			alice.StoreFile(filename1, content1)
			bob.StoreFile(filename2, content2)

			// Check datastore for key reuse
			// We will look at the key used to store files
			storageKeyAlice := hex.EncodeToString(userlib.Hash([]byte(filename1 + username1))[:16])
			storageKeyBob := hex.EncodeToString(userlib.Hash([]byte(filename2 + username2))[:16])

			// Expect that the storage keys are different
			Expect(storageKeyAlice).ToNot(Equal(storageKeyBob))

			// Load the files
			dataAlice, _ := alice.LoadFile(filename1)
			dataBob, _ := bob.LoadFile(filename2)

			// Expect that the loaded files are correctly decrypted and are not equal (if the same key was reused for encryption, their decrypted content might be equal)
			Expect(dataAlice).To(Equal(content1))
			Expect(dataBob).To(Equal(content2))
			Expect(dataAlice).ToNot(Equal(dataBob))
		})

	})
	Describe("LoadFile", func() {
		It("should store and retrieve a file for a single user", func() {
			evanBot, _ := client.InitUser("EvanBot", "password123")
			_ = evanBot.StoreFile("foods.txt", []byte("pancakes"))
			content, _ := evanBot.LoadFile("foods.txt")
			Expect(string(content)).To(Equal("pancakes"))
		})
		It("should overwrite an existing file's content", func() {
			evanBot, _ := client.InitUser("EvanBot", "password123")
			_ = evanBot.StoreFile("foods.txt", []byte("cookies"))
			content, _ := evanBot.LoadFile("foods.txt")
			Expect(string(content)).To(Equal("cookies"))
		})
		It("should maintain namespace isolation between users", func() {
			evanBot, _ := client.InitUser("EvanBot", "password123")
			codaBot, _ := client.InitUser("CodaBot", "password456")

			_ = evanBot.StoreFile("foods.txt", []byte("pancakes"))
			_ = codaBot.StoreFile("foods.txt", []byte("waffles"))

			evanContent, _ := evanBot.LoadFile("foods.txt")
			codaContent, _ := codaBot.LoadFile("foods.txt")

			Expect(string(evanContent)).To(Equal("pancakes"))
			Expect(string(codaContent)).To(Equal("waffles"))
		})
		It("should append content to an existing file", func() {
			evanBot, _ := client.InitUser("EvanBot", "password123")
			_ = evanBot.StoreFile("foods.txt", []byte("cookies"))
			_ = evanBot.AppendToFile("foods.txt", []byte(" and pancakes"))
			content, _ := evanBot.LoadFile("foods.txt")
			Expect(string(content)).To(Equal("cookies and pancakes"))
		})
		It("should return error when appending to a non-existing file", func() {
			evanBot, _ := client.InitUser("EvanBot", "password123")
			err := evanBot.AppendToFile("drinks.txt", []byte("soda"))
			Expect(err).ToNot(BeNil())
		})
		It("should use efficient bandwidth for append operations", func() {
			evanBot, _ := client.InitUser("EvanBot", "password123")
			_ = evanBot.StoreFile("largeFile.txt", make([]byte, 10*1024*1024))

			// Measure bandwidth before append
			beforeBandwidth := userlib.DatastoreGetBandwidth()

			_ = evanBot.AppendToFile("largeFile.txt", make([]byte, 10*1024))

			// Measure bandwidth after append
			afterBandwidth := userlib.DatastoreGetBandwidth()

			Expect(afterBandwidth - beforeBandwidth).To(BeNumerically("~", 10*1024, 256)) // consider a buffer of 256 bytes
		})
		It("should correctly handle hex encoded filenames", func() {
			evanBot, _ := client.InitUser("EvanBot", "password123")
			hexFilename := hex.EncodeToString([]byte("foods.txt"))
			_ = evanBot.StoreFile(hexFilename, []byte("pancakes"))
			content, _ := evanBot.LoadFile(hexFilename)
			Expect(string(content)).To(Equal("pancakes"))
		})
		It("should correctly handle special character filenames", func() {
			evanBot, _ := client.InitUser("EvanBot", "password123")
			specialFilename := "!@#$%^&*()_+-={}[]|;:'<>,.?~"
			_ = evanBot.StoreFile(specialFilename, []byte("pancakes"))
			content, _ := evanBot.LoadFile(specialFilename)
			Expect(string(content)).To(Equal("pancakes"))
		})
		It("should handle appending to an empty file", func() {
			evanBot, _ := client.InitUser("EvanBot", "password123")
			_ = evanBot.StoreFile("empty.txt", []byte(""))
			_ = evanBot.AppendToFile("empty.txt", []byte("content"))
			content, _ := evanBot.LoadFile("empty.txt")
			Expect(string(content)).To(Equal("content"))
		})
		It("should handle loading non-existent files with weird characters", func() {
			evanBot, _ := client.InitUser("EvanBot", "password123")
			_, err := evanBot.LoadFile("nonExistent@#$$%^&")
			Expect(err).ToNot(BeNil())
		})
		It("should prevent overwriting a file with same key", func() {
			evanBot, _ := client.InitUser("EvanBot", "password123")
			_ = evanBot.StoreFile("keyTest.txt", []byte("original"))

			// Simulate attacker action: guessing the key and overwriting the content
			possibleKey := userlib.Hash([]byte("keyTest.txt" + "EvanBot"))[:16]
			possibleKeY, _ := uuid.FromBytes(possibleKey)
			userlib.DatastoreSet(possibleKeY, []byte("attacker content"))

			content, _ := evanBot.LoadFile("keyTest.txt")
			Expect(string(content)).ToNot(Equal("attacker content"))
		})
		It("should handle very long filenames", func() {
			evanBot, _ := client.InitUser("EvanBot", "password123")
			longFilename := strings.Repeat("a", 10000) // 10,000 character filename
			_ = evanBot.StoreFile(longFilename, []byte("content"))
			content, _ := evanBot.LoadFile(longFilename)
			Expect(string(content)).To(Equal("content"))
		})
		It("should handle appending very large content", func() {
			evanBot, _ := client.InitUser("EvanBot", "password123")
			_ = evanBot.StoreFile("bigFile.txt", []byte("initial"))
			bigContent := []byte(strings.Repeat("a", 10*1024*1024)) // 10 MB append
			_ = evanBot.AppendToFile("bigFile.txt", bigContent)
			content, _ := evanBot.LoadFile("bigFile.txt")
			Expect(content[len(content)-10:]).To(Equal(bigContent[len(bigContent)-10:])) // Check last 10 bytes of content
		})

	})
	Describe("ComplexRevocationTests", func() {

		Context("Multiple Users and Files", func() {

			It("Should handle revocation across multiple users and files correctly", func() {
				// Initialize 10 users
				users := make([]*client.User, 10)
				for i := 0; i < 10; i++ {
					users[i], _ = client.InitUser(fmt.Sprintf("User%d", i+1), "password")
				}

				// User1 stores 20 files
				for i := 0; i < 20; i++ {
					users[0].StoreFile(fmt.Sprintf("file%d", i+1), []byte(fmt.Sprintf("Content of file%d", i+1)))
				}

				// User1 shares each file with all other users
				for i := 0; i < 20; i++ {
					for j := 1; j < 10; j++ {
						invite, _ := users[0].CreateInvitation(fmt.Sprintf("file%d", i+1), fmt.Sprintf("User%d", j+1))
						users[j].AcceptInvitation(fmt.Sprintf("User1"), invite, fmt.Sprintf("file%d_shared", i+1))
					}
				}

				// Each user tries to access each file and should succeed
				for i := 0; i < 20; i++ {
					for j := 1; j < 10; j++ {
						_, err := users[j].LoadFile(fmt.Sprintf("file%d_shared", i+1))
						Expect(err).ToNot(HaveOccurred())
					}
				}

				// User1 revokes User2's access to all files
				for i := 0; i < 20; i++ {
					users[0].RevokeAccess(fmt.Sprintf("file%d", i+1), "User2")
				}

				// User2 tries to access each file and should fail
				for i := 0; i < 20; i++ {
					_, err := users[1].LoadFile(fmt.Sprintf("file%d_shared", i+1))
					Expect(err).To(HaveOccurred())
				}

				// User2 (revoked user) turns malicious and tampers with the datastore
				for UUID, _ := range userlib.DatastoreGetMap() {
					tamperedData := []byte("Malicious content by User2")
					userlib.DatastoreSet(UUID, tamperedData)
				}

				// User1 tries to retrieve the files and should detect tampering
				for i := 0; i < 20; i++ {
					_, err := users[0].LoadFile(fmt.Sprintf("file%d", i+1))
					Expect(err).To(HaveOccurred())
				}
			})

		})

	})
	Describe("Fuzz Testing for Edge Cases", func() {

		Describe("Edge Cases", func() {

			It("should handle username collisions", func() {
				_, err1 := client.InitUser("user_collide", "password1")
				_, err2 := client.InitUser("user_collide", "password2")
				Expect(err1).To(BeNil())
				Expect(err2).NotTo(BeNil()) // Expect an error because username already exists
			})

			It("should handle case-sensitive usernames", func() {
				_, err1 := client.InitUser("UserCase", "password1")
				_, err2 := client.InitUser("usercase", "password2")
				Expect(err1).To(BeNil())
				Expect(err2).To(BeNil()) // Both should succeed because usernames are case-sensitive
			})

			It("should handle repeated login attempts with wrong password", func() {
				_, _ = client.InitUser("user_wrong_pass", "correct_password")
				for i := 0; i < 100; i++ {
					_, err := client.GetUser("user_wrong_pass", "wrong_password")
					Expect(err).NotTo(BeNil()) // Expecting an error because password is incorrect
				}
			})

			It("should handle storing and loading an empty file", func() {
				user, _ := client.InitUser("empty_file_user", "password")
				err := user.StoreFile("empty_file", []byte{})
				Expect(err).To(BeNil())
				content, err := user.LoadFile("empty_file")
				Expect(err).To(BeNil())
				Expect(len(content)).To(Equal(0))
			})

			It("should handle attempts to overwrite shared files", func() {
				user1, _ := client.InitUser("user1", "password1")
				user2, _ := client.InitUser("user2", "password2")

				err := user1.StoreFile("shared_file", []byte("original content"))
				Expect(err).To(BeNil())

				invitation, err := user1.CreateInvitation("shared_file", "user2")
				Expect(err).To(BeNil())

				err = user2.AcceptInvitation("user1", invitation, "shared_file")
				Expect(err).To(BeNil())

				// Attempt to overwrite the shared file
				err = user2.StoreFile("shared_file", []byte("new content"))
				Expect(err).To(BeNil())

				content, err := user1.LoadFile("shared_file")
				Expect(err).To(BeNil())
				Expect(string(content)).To(Equal("new content"))
			})

			It("should handle revoking access from a non-shared user", func() {
				user1, _ := client.InitUser("user1", "password1")
				_, _ = client.InitUser("user2", "password2")

				err := user1.StoreFile("non_shared_file", []byte("content"))
				Expect(err).To(BeNil())

				// Attempt to revoke access from a user who hasn't been shared with
				err = user1.RevokeAccess("non_shared_file", "user2")
				Expect(err).NotTo(BeNil()) // Expecting an error because user2 hasn't been shared with
			})

			It("should handle sharing a file with oneself", func() {
				user, _ := client.InitUser("self_share_user", "password")
				err := user.StoreFile("self_share_file", []byte("content"))
				Expect(err).To(BeNil())

				// Attempt to share with oneself
				_, err = user.CreateInvitation("self_share_file", "self_share_user")
				Expect(err).NotTo(BeNil()) // Expecting an error because sharing with oneself is not logical
			})

		})
		Describe("More Edge Cases", func() {

			It("should handle repeatedly creating and deleting users", func() {
				for i := 0; i < 50; i++ {
					username := fmt.Sprintf("repeated_user_%d", i)
					password := fmt.Sprintf("password_%d", i)
					user, err := client.InitUser(username, password)
					Expect(err).To(BeNil())

					err = user.StoreFile("file", []byte("content"))
					Expect(err).To(BeNil())

					// Simulating "deletion" by overwriting the user's data (as there's no direct delete user API)
					err = user.StoreFile("file", []byte{})
					Expect(err).To(BeNil())
				}
			})

			It("should handle storing files with same name by different users", func() {
				user1, _ := client.InitUser("user1_samefile", "password1")
				user2, _ := client.InitUser("user2_samefile", "password2")

				content1 := "content from user1"
				content2 := "content from user2"

				err := user1.StoreFile("samefile", []byte(content1))
				Expect(err).To(BeNil())

				err = user2.StoreFile("samefile", []byte(content2))
				Expect(err).To(BeNil())

				loadedContent1, err := user1.LoadFile("samefile")
				Expect(err).To(BeNil())
				Expect(string(loadedContent1)).To(Equal(content1))

				loadedContent2, err := user2.LoadFile("samefile")
				Expect(err).To(BeNil())
				Expect(string(loadedContent2)).To(Equal(content2))
			})

			It("should handle sharing with a user and then revoking immediately", func() {
				user1, _ := client.InitUser("user1_revoke", "password1")
				user2, _ := client.InitUser("user2_revoke", "password2")

				err := user1.StoreFile("immediate_revoke_file", []byte("content"))
				Expect(err).To(BeNil())

				invitation, err := user1.CreateInvitation("immediate_revoke_file", "user2_revoke")
				Expect(err).To(BeNil())

				err = user2.AcceptInvitation("user1_revoke", invitation, "immediate_revoke_file")
				Expect(err).To(BeNil())

				err = user1.RevokeAccess("immediate_revoke_file", "user2_revoke")
				Expect(err).To(BeNil())

				_, err = user2.LoadFile("immediate_revoke_file")
				Expect(err).NotTo(BeNil()) // Expecting an error because access was revoked
			})

		})

	})
	Describe("Fuzz Testing for Share and Revoke", func() {

		Describe("Share and Revoke Edge Cases", func() {

			It("should allow authorized users to read, overwrite, append, and share", func() {
				owner, _ := client.InitUser("owner", "password")
				recipient, _ := client.InitUser("recipient", "password")

				filename := "testfile"
				originalContent := []byte("original content")
				err := owner.StoreFile(filename, originalContent)
				Expect(err).To(BeNil())

				invitation, err := owner.CreateInvitation(filename, "recipient")
				Expect(err).To(BeNil())

				err = recipient.AcceptInvitation("owner", invitation, filename)
				Expect(err).To(BeNil())

				// Authorized users (both owner and recipient) should be able to read
				content, err := owner.LoadFile(filename)
				Expect(err).To(BeNil())
				Expect(content).To(Equal(originalContent))

				content, err = recipient.LoadFile(filename)
				Expect(err).To(BeNil())
				Expect(content).To(Equal(originalContent))

				// Overwrite file
				newContent := []byte("new content")
				err = recipient.StoreFile(filename, newContent)
				Expect(err).To(BeNil())

				// Append to file
				appendContent := []byte(" appended content")
				err = recipient.AppendToFile(filename, appendContent)
				Expect(err).To(BeNil())

				// Share file further (though this is not detailed in your given scenario)
				recipient2, _ := client.InitUser("recipient2", "password")
				invitation2, err := recipient.CreateInvitation(filename, "recipient2")
				Expect(err).To(BeNil())

				err = recipient2.AcceptInvitation("recipient", invitation2, filename)
				Expect(err).To(BeNil())
			})

			It("should handle revoking access properly", func() {
				owner, _ := client.InitUser("owner_revoke", "password")
				recipient, _ := client.InitUser("recipient_revoke", "password")

				filename := "revokefile"
				err := owner.StoreFile(filename, []byte("content"))
				Expect(err).To(BeNil())

				invitation, err := owner.CreateInvitation(filename, "recipient_revoke")
				Expect(err).To(BeNil())

				err = recipient.AcceptInvitation("owner_revoke", invitation, filename)
				Expect(err).To(BeNil())

				err = owner.RevokeAccess(filename, "recipient_revoke")
				Expect(err).To(BeNil())

				_, err = recipient.LoadFile(filename)
				Expect(err).NotTo(BeNil())

			})

		})

	})
	Describe("Advanced Fuzz Testing", func() {
		Describe("More Advanced Test Cases", func() {

			measureBandwidth := func(probe func()) (bandwidth int) {
				before := userlib.DatastoreGetBandwidth()
				probe()
				after := userlib.DatastoreGetBandwidth()
				return after - before
			}
			_ = measureBandwidth

			It("should observe changes in the datastore after various operations", func() {
				user, _ := client.InitUser("observe_user", "password")
				filename := "observe_file"
				content := []byte("observational content")

				datastoreBefore := userlib.DatastoreGetMap()
				user.StoreFile(filename, content)
				datastoreAfter := userlib.DatastoreGetMap()

				Expect(len(datastoreBefore)).To(BeNumerically("<=", len(datastoreAfter)))
			})

			It("should handle tampering with file contents", func() {
				user, _ := client.InitUser("content_tamper_user", "password")
				filename := "content_tamper_file"
				content := []byte("content for tampering")

				err := user.StoreFile(filename, content)
				Expect(err).To(BeNil())

				// Tamper with the datastore to simulate an attacker modifying file contents
				datastoreMap := userlib.DatastoreGetMap()
				for k := range datastoreMap {
					datastoreMap[k] = []byte("tampered content")
				}

				_, err = user.LoadFile(filename)
				Expect(err).NotTo(BeNil()) // Error should be raised due to tampering
			})

			It("should ensure integrity of shared files after tampering", func() {
				owner, _ := client.InitUser("integrity_owner", "password")
				recipient, _ := client.InitUser("integrity_recipient", "password")

				filename := "integrity_file"
				content := []byte("content for integrity")
				err := owner.StoreFile(filename, content)
				Expect(err).To(BeNil())

				invitation, err := owner.CreateInvitation(filename, "integrity_recipient")
				Expect(err).To(BeNil())

				err = recipient.AcceptInvitation("integrity_owner", invitation, filename)
				Expect(err).To(BeNil())

				// Now, tamper with the datastore contents
				datastoreMap := userlib.DatastoreGetMap()
				for k := range datastoreMap {
					datastoreMap[k] = []byte("tampered invitation content")
				}

				_, err = recipient.LoadFile(filename)
				Expect(err).NotTo(BeNil()) // Expecting an error due to tampering

				// Further tests can involve:
				// - Tampering after sharing, before accepting, etc.
				// - Checking the integrity of shared files after various tampering scenarios
			})

			It("should handle tampering with metadata (if any)", func() {
				user, _ := client.InitUser("metadata_user", "password")
				filename := "metadata_file"
				content := []byte("metadata content")

				err := user.StoreFile(filename, content)
				Expect(err).To(BeNil())

				// Tamper with the datastore to simulate an attacker modifying metadata
				// (assuming that metadata is stored in some entries)
				datastoreMap := userlib.DatastoreGetMap()
				for k := range datastoreMap {
					datastoreMap[k] = append(datastoreMap[k], []byte("tampered metadata")...)
				}

				_, err = user.LoadFile(filename)
				Expect(err).NotTo(BeNil()) // Error should be raised due to tampering
			})

		})
		Describe("Advanced Test Cases", func() {

			measureBandwidth := func(probe func()) (bandwidth int) {
				before := userlib.DatastoreGetBandwidth()
				probe()
				after := userlib.DatastoreGetBandwidth()
				return after - before
			}

			It("should handle tampering with datastore directly", func() {
				user, _ := client.InitUser("tamper_user", "password")
				filename := "tamper_file"
				content := []byte("initial content")

				err := user.StoreFile(filename, content)
				Expect(err).To(BeNil())

				// Tamper with the datastore directly to simulate an attacker
				datastoreMap := userlib.DatastoreGetMap()
				for k := range datastoreMap {
					datastoreMap[k] = []byte("tampered data")
				}

				_, err = user.LoadFile(filename)
				Expect(err).NotTo(BeNil()) // Error should be raised due to tampering
			})

			It("should measure efficiency when appending to a file", func() {
				user, _ := client.InitUser("efficiency_user", "password")
				filename := "efficiency_file"
				initialContent := []byte("initial content")
				err := user.StoreFile(filename, initialContent)
				Expect(err).To(BeNil())

				appendContent := []byte(" appended content")
				bw := measureBandwidth(func() {
					user.AppendToFile(filename, appendContent)
				})

				Expect(bw).To(BeNumerically("<", 10000)) // Just an arbitrary number, you can set an actual limit
			})

			It("should handle sharing and revocation after datastore tampering", func() {
				owner, _ := client.InitUser("owner_tamper", "password")
				recipient, _ := client.InitUser("recipient_tamper", "password")

				filename := "tamper_share_file"
				err := owner.StoreFile(filename, []byte("content"))
				Expect(err).To(BeNil())

				invitation, err := owner.CreateInvitation(filename, "recipient_tamper")
				Expect(err).To(BeNil())

				// Tamper with the datastore before accepting the invitation
				datastoreMap := userlib.DatastoreGetMap()
				for k := range datastoreMap {
					datastoreMap[k] = []byte("tampered invitation data")
				}

				err = recipient.AcceptInvitation("owner_tamper", invitation, filename)
				Expect(err).NotTo(BeNil())
			})

		})

	})
	Describe("Advanced Fuzz Testing: Deep Dive", func() {

		Describe("Deep Dive Test Cases", func() {

			It("should handle tampering with user credentials", func() {
				user, _ := client.InitUser("credential_user", "password")
				filename := "credential_file"
				content := []byte("credential content")

				err := user.StoreFile(filename, content)
				Expect(err).To(BeNil())

				// Tamper with the datastore to simulate an attacker modifying user credentials
				datastoreMap := userlib.DatastoreGetMap()
				for k := range datastoreMap {
					datastoreMap[k] = []byte("fake credentials")
				}

				_, err = client.GetUser("credential_user", "password")
				Expect(err).NotTo(BeNil()) // Error should be raised due to tampering
			})

			It("should ensure shared files' confidentiality after datastore tampering", func() {
				owner, _ := client.InitUser("confidential_owner", "password")
				recipient, _ := client.InitUser("confidential_recipient", "password")

				filename := "confidential_file"
				content := []byte("confidential content")
				err := owner.StoreFile(filename, content)
				Expect(err).To(BeNil())

				invitation, err := owner.CreateInvitation(filename, "confidential_recipient")
				Expect(err).To(BeNil())

				// Tamper with the datastore before accepting the invitation
				datastoreMap := userlib.DatastoreGetMap()
				for k := range datastoreMap {
					datastoreMap[k] = []byte("tampered confidential content")
				}

				err = recipient.AcceptInvitation("confidential_owner", invitation, filename)
				Expect(err).NotTo(BeNil()) // Error should be raised due to tampering

				_, err = recipient.LoadFile(filename)
				Expect(err).NotTo(BeNil()) // Error should be raised due to tampering

			})

			It("should prevent unauthorized access to files", func() {
				owner, _ := client.InitUser("authorized_owner", "password")
				intruder, _ := client.InitUser("intruder", "password")

				filename := "authorized_file"
				content := []byte("authorized content")
				err := owner.StoreFile(filename, content)
				Expect(err).To(BeNil())

				_, err = intruder.LoadFile(filename)
				Expect(err).NotTo(BeNil()) // Error should be raised since intruder is not authorized
			})

			It("should handle tampering with file sharing invitations", func() {
				owner, _ := client.InitUser("invite_owner", "password")
				recipient, _ := client.InitUser("invite_recipient", "password")

				filename := "invite_file"
				content := []byte("invite content")
				err := owner.StoreFile(filename, content)
				Expect(err).To(BeNil())

				_, err = owner.CreateInvitation(filename, "invite_recipient")
				Expect(err).To(BeNil())

				// Tamper with the invitation

				tamperedInvitation := uuid.New()

				err = recipient.AcceptInvitation("invite_owner", tamperedInvitation, filename)
				Expect(err).NotTo(BeNil()) // Error should be raised due to tampering
			})

		})

	})
	Describe("Advanced Sharing and Revocation Tests", func() {

		Describe("Revoked User Adversary Tests", func() {

			It("should prevent a revoked user from accessing the file after revocation", func() {
				owner, _ := client.InitUser("owner", "password")
				sharedUser, _ := client.InitUser("sharedUser", "password")
				filename := "sharedFile"
				content := []byte("initial content")
				err := owner.StoreFile(filename, content)
				Expect(err).To(BeNil())

				invitation, err := owner.CreateInvitation(filename, "sharedUser")
				Expect(err).To(BeNil())

				err = sharedUser.AcceptInvitation("owner", invitation, "receivedFile")
				Expect(err).To(BeNil())

				err = owner.RevokeAccess(filename, "sharedUser")
				Expect(err).To(BeNil())

				_, err = sharedUser.LoadFile("receivedFile")
				Expect(err).NotTo(BeNil()) // Error should be raised due to revocation
			})

			It("should not allow revoked users to modify the file", func() {
				owner, _ := client.InitUser("owner2", "password")
				sharedUser, _ := client.InitUser("sharedUser2", "password")
				filename := "anotherSharedFile"
				content := []byte("initial data")
				err := owner.StoreFile(filename, content)
				Expect(err).To(BeNil())

				invitation, err := owner.CreateInvitation(filename, "sharedUser2")
				Expect(err).To(BeNil())

				err = sharedUser.AcceptInvitation("owner2", invitation, "anotherReceivedFile")
				Expect(err).To(BeNil())

				err = owner.RevokeAccess(filename, "sharedUser2")
				Expect(err).To(BeNil())

				err = sharedUser.AppendToFile("anotherReceivedFile", []byte(" malicious append"))
				Expect(err).NotTo(BeNil()) // Error should be raised due to revocation
			})

			It("should prevent a revoked user adversary from discerning updates", func() {
				owner, _ := client.InitUser("owner3", "password")
				adversary, _ := client.InitUser("adversary", "password")
				filename := "fileForAdversary"
				content := []byte("content before attack")
				err := owner.StoreFile(filename, content)
				Expect(err).To(BeNil())

				invitation, err := owner.CreateInvitation(filename, "adversary")
				Expect(err).To(BeNil())

				err = adversary.AcceptInvitation("owner3", invitation, "adversaryFile")
				Expect(err).To(BeNil())

				err = owner.RevokeAccess(filename, "adversary")
				Expect(err).To(BeNil())

				// Adversary trying to discern updates
				_, err = adversary.LoadFile("adversaryFile")
				Expect(err).NotTo(BeNil()) // Error should be raised due to revocation
				err = adversary.AppendToFile("adversaryFile", []byte(" malicious append"))
				Expect(err).NotTo(BeNil()) // Error should be raised due to revocation

				err = owner.AppendToFile(filename, []byte(" post-revocation update"))
				Expect(err).To(BeNil())

				_, err = adversary.LoadFile("adversaryFile")
				Expect(err).NotTo(BeNil()) // Error should be raised due to revocation
			})

		})

	})
	Describe("Advanced Manipulation and Access Tests", func() {

		Describe("Revoked User State Manipulation Tests", func() {

			It("should prevent a revoked user from regaining access by manipulating datastore", func() {
				owner, _ := client.InitUser("owner4", "password")
				revokedUser, _ := client.InitUser("revokedUser", "password")
				filename := "manipulationTestFile"
				content := []byte("content to manipulate")
				err := owner.StoreFile(filename, content)
				Expect(err).To(BeNil())

				invitation, err := owner.CreateInvitation(filename, "revokedUser")
				Expect(err).To(BeNil())

				err = revokedUser.AcceptInvitation("owner4", invitation, "myFile")
				Expect(err).To(BeNil())

				err = owner.RevokeAccess(filename, "revokedUser")
				Expect(err).To(BeNil())

				// Manipulate datastore in an attempt to regain access
				datastoreMap := userlib.DatastoreGetMap()
				for k, _ := range datastoreMap {
					userlib.DatastoreSet(k, []byte("tampered_data_for_access"))
				}

				_, err = revokedUser.LoadFile("myFile")
				Expect(err).NotTo(BeNil()) // Error should be raised as the user is still revoked
			})

			It("should allow shared users to access the file even after other users are revoked", func() {
				owner, _ := client.InitUser("owner5", "password")
				user1, _ := client.InitUser("user1", "password")
				user2, _ := client.InitUser("user2", "password")

				filename := "sharedAmongMultiple"
				content := []byte("shared content")
				err := owner.StoreFile(filename, content)
				Expect(err).To(BeNil())

				invitation1, err := owner.CreateInvitation(filename, "user1")
				Expect(err).To(BeNil())
				invitation2, err := owner.CreateInvitation(filename, "user2")
				Expect(err).To(BeNil())

				err = user1.AcceptInvitation("owner5", invitation1, "file1")
				Expect(err).To(BeNil())
				err = user2.AcceptInvitation("owner5", invitation2, "file2")
				Expect(err).To(BeNil())

				err = owner.RevokeAccess(filename, "user1")
				Expect(err).To(BeNil())

				// User1 should not be able to access the file
				_, err = user1.LoadFile("file1")
				Expect(err).NotTo(BeNil())

				// User2 should still be able to access the file
				loadedContent, err := user2.LoadFile("file2")
				Expect(err).To(BeNil())
				Expect(loadedContent).To(Equal(content))
			})

		})
	})
	Describe("Integrity and Advanced Attacks Tests", func() {

		Describe("Integrity after Revocations and Acceptances", func() {

			It("should maintain content integrity after multiple revocations and acceptances", func() {
				owner, _ := client.InitUser("owner6", "password")
				userA, _ := client.InitUser("userA", "password")
				userB, _ := client.InitUser("userB", "password")

				filename := "integrityTestFile"
				content := []byte("initial content")
				err := owner.StoreFile(filename, content)
				Expect(err).To(BeNil())

				invitationA, err := owner.CreateInvitation(filename, "userA")
				Expect(err).To(BeNil())

				err = userA.AcceptInvitation("owner6", invitationA, "fileA")
				Expect(err).To(BeNil())

				// UserA shares with UserB
				invitationB, err := userA.CreateInvitation("fileA", "userB")
				Expect(err).To(BeNil())

				err = userB.AcceptInvitation("userA", invitationB, "fileB")
				Expect(err).To(BeNil())

				// Owner revokes UserA
				err = owner.RevokeAccess(filename, "userA")
				Expect(err).To(BeNil())

				// UserA shouldn't be able to access the file
				_, err = userA.LoadFile("fileA")
				Expect(err).NotTo(BeNil())

				// UserB should also lose access due to revocation of UserA
				_, err = userB.LoadFile("fileB")
				Expect(err).NotTo(BeNil())

				// Re-sharing the file with UserA
				invitationA2, err := owner.CreateInvitation(filename, "userA")
				Expect(err).To(BeNil())

				err = userA.AcceptInvitation("owner6", invitationA2, "fileA2")
				Expect(err).To(BeNil())

				loadedContent, err := userA.LoadFile("fileA2")
				Expect(err).To(BeNil())
				Expect(loadedContent).To(Equal(content))
			})

		})

		Describe("Advanced Attacks on Internal Mechanisms", func() {

			It("should resist tampering with internal encryption or structures", func() {
				user, _ := client.InitUser("user7", "password")
				filename := "internalAttackFile"
				content := []byte("content to be tampered")
				err := user.StoreFile(filename, content)
				Expect(err).To(BeNil())

				// Directly tampering with datastore values
				datastoreMap := userlib.DatastoreGetMap()
				for k, _ := range datastoreMap {
					userlib.DatastoreSet(k, []byte("direct_tampering"))
				}

				// Trying to load the file after tampering
				_, err = user.LoadFile(filename)
				Expect(err).NotTo(BeNil()) // Error should be raised as the datastore is tampered with
			})

			It("should resist potential replay attacks", func() {
				user, _ := client.InitUser("user8", "password")
				attacker, _ := client.InitUser("attacker", "password")

				filename := "replayAttackFile"
				content := []byte("content for replay")
				err := user.StoreFile(filename, content)
				Expect(err).To(BeNil())

				// Attacker tries to use an old invitation UUID
				invitation, err := user.CreateInvitation(filename, "attacker")
				Expect(err).To(BeNil())

				err = attacker.AcceptInvitation("user8", invitation, "stolenFile")
				Expect(err).To(BeNil())

				// User revokes the attacker
				err = user.RevokeAccess(filename, "attacker")
				Expect(err).To(BeNil())

				// Attacker tries to use the old invitation again (replay attack)
				err = attacker.AcceptInvitation("user8", invitation, "stolenFile2")
				Expect(err).NotTo(BeNil()) // Error should be raised as this is a replay attack
			})

		})

	})
	Describe("Impersonation Attack Tests", func() {
		It("Should prevent impersonation attacks", func() {
			user, _ := client.InitUser("userImpersonation", "password")
			user.StoreFile("file1", []byte("Private content"))

			// Simulating an attacker trying to impersonate the user
			attacker, err := client.GetUser("userImpersonation", "wrong_password")
			Expect(attacker).To(BeNil()) // Assert that the attacker object should be nil
			Expect(err).ToNot(BeNil())

			if attacker != nil {
				content, _ := attacker.LoadFile("file1")
				Expect(content).To(BeNil())
			}
		})

	})
	Describe("Brute Force Attack Tests", func() {
		It("Should resist brute force attacks", func() {
			user, _ := client.InitUser("userBruteForce", "uniqPass!@#")
			user.StoreFile("file3", []byte("Brute force content"))

			for i := 0; i < 10000; i++ {
				pass := fmt.Sprintf("try%d", i)
				attacker, _ := client.GetUser("userBruteForce", pass)
				content, _ := attacker.LoadFile("file3")
				Expect(content).To(BeNil())
			}
		})
	})
	Describe("Key Derivation Attacks", func() {
		It("Should resist attempts to manipulate or brute force key derivations", func() {
			alice, err := client.InitUser("alice", "password123")
			Expect(err).To(BeNil())

			err = alice.StoreFile("keyTestFile", []byte("key test data"))
			Expect(err).To(BeNil())

			// Attempt to derive keys and tamper with the Datastore
			for i := 0; i < 1000; i++ {
				possibleKey := userlib.Argon2Key([]byte(fmt.Sprintf("possiblePassword%d", i)), []byte("alice"), 16)
				possibleUUID := uuid.NewSHA1(uuid.Nil, possibleKey)
				ds := userlib.DatastoreGetMap()
				if _, ok := ds[possibleUUID]; ok {
					ds[possibleUUID] = []byte("tampered data")
				}
			}

			// Alice tries to load the file
			_, err = alice.LoadFile("keyTestFile")
			Expect(err).To(BeNil()) // Even with tampering attempts, Alice should still access her file successfully
		})
	})

	Describe("Replay Attack on User Initialization", func() {
		It("Should detect and prevent replay attacks during user initialization", func() {
			_, err := client.InitUser("alice", "password123")
			Expect(err).To(BeNil())

			// Attempt to initialize Alice again with the same credentials
			_, err = client.InitUser("alice", "password123")
			Expect(err).ToNot(BeNil()) // Expect an error since Alice already exists
		})
	})

	Describe("StoreFile Tests", func() {

		It("Should handle attempts to store files with same filename but different content", func() {
			user, err := client.InitUser("Alice", "password123")
			err = user.StoreFile("testFile", []byte("initial content"))
			Expect(err).To(BeNil())
			if err != nil {
				fmt.Sprintf("Error: %v", err)
			}
			// Attempt to store a file with the same filename but different content
			err = user.StoreFile("testFile", []byte("new content"))
			loadedContent, err := user.LoadFile("testFile")
			Expect(err).To(BeNil())
			Expect(loadedContent).To(Equal([]byte("new content")))
		})

		It("Should maintain confidentiality of file contents and filenames during storage", func() {
			user, err := client.InitUser("Bob", "password456")
			err = user.StoreFile("secretFile", []byte("secret content"))
			Expect(err).To(BeNil())
			storageKey, _, _, err := generateAllKeys("secretFile", "password456", "Bob")

			data, found := userlib.DatastoreGet(storageKey)
			Expect(found).To(BeTrue())
			Expect(data).NotTo(ContainSubstring("secret content"))
		})

		It("Should detect tampering after storing a file", func() {
			user, err := client.InitUser("Charlie", "password789")
			err = user.StoreFile("testFile", []byte("original content"))
			Expect(err).To(BeNil())
			storageKey, _, _, err := generateAllKeys("testFile", "password789", "Charlie")

			// External tampering of the file content in the Datastore
			userlib.DatastoreSet(storageKey, []byte("tampered content"))

			// Attempt to load the file should either return an error or detect the tampering
			_, err = user.LoadFile("testFile")
			Expect(err).NotTo(BeNil())
		})

	})

})

var _ = Describe("Security Tests", func() {
	userlib.DebugOutput = false

	// A few user declarations that may be used for testing. Remember to initialize these before you
	// attempt to use them!
	var alice *client.User
	_ = alice
	alicePassword := "dafk;u24Erfwgpeaivdsnzc;l n;lk"
	_ = alicePassword
	var bob *client.User
	_ = bob
	bobPassword := "asdfasd"
	_ = bobPassword
	var charles *client.User
	_ = charles
	var david *client.User
	_ = david
	var doris *client.User
	_ = doris
	var eve *client.User
	_ = eve
	var frank *client.User
	_ = frank
	var grace *client.User
	_ = grace
	var horace *client.User
	_ = horace
	var ira *client.User
	_ = ira
	// These declarations may be useful for multi-session testing.
	var alicePhone *client.User
	_ = alicePhone
	var aliceLaptop *client.User
	_ = aliceLaptop
	var aliceDesktop *client.User
	_ = aliceDesktop
	var bobPhone *client.User
	_ = bobPhone
	var bobLaptop *client.User
	_ = bobLaptop
	var bobDesktop *client.User
	_ = bobDesktop
	var err error
	_ = err

	// A bunch of filenames that may be useful.
	aliceFile := "aliadfaslvjclki2e	frwadsvlelnfFEFS:DJ:TEK#WPJU949240-00wds  {}{}{^&*#$)()(*@#)_)+#%__\x00\x90\xAB"
	_ = aliceFile
	bobFile := "adsflcjo;	2ijwef;adlcsvnDSLKF:zxlndzcv lnlkd \x00\x90\xAB"
	_ = bobFile
	charlesFile := "charleDsFile.txt\x9e42jerwfldsCLnlx;zkn;lkweu4	rtejwflkdsCL;dsee!*@*#$(" +
		")_$%T^)_}}}}}|||324524	TIQ-R0||||||\\\\\\"
	_ = charlesFile
	dorisFile := "dodfascxv ;3932rijewfpadsi ,dfae2tepwfgdsvazck m!@@##$W%^(" +
		"$_W%)^Y%_E)ITGzdfpvcjopzfsvl;xcmfDefjpwfmvaclwf'pEJxt"
	_ = dorisFile

	eveFile := "eveFile.txtAADFA\x9e909dSPVFJC]x\\]}}{FD}SV{C}}"
	_ = eveFile
	frankFile := "frankFile.txt"
	_ = frankFile
	graceFile := "graceFile.txt"
	_ = graceFile
	horaceFile := "horaceFile.txt"
	_ = horaceFile
	iraFile := "iraFile.txt"
	_ = iraFile

	measureBandwidth := func(probe func()) (bandwidth int) {
		before := userlib.DatastoreGetBandwidth()
		probe()
		after := userlib.DatastoreGetBandwidth()
		return after - before
	}
	_ = measureBandwidth
	BeforeEach(func() {
		userlib.DatastoreClear()
		userlib.KeystoreClear()
	})
	It("should resist brute force attacks on known usernames with common passwords", func() {
		knownUsernames := []string{"Alice", "Bob", "Charlie"}
		commonPasswords := []string{"password", "123456", "letmein", "welcome"}

		for _, username := range knownUsernames {
			for _, password := range commonPasswords {
				attackStorageKey, _, _, _ := generateAllKeys("commonFile", password, username)
				data, ok := userlib.DatastoreGet(attackStorageKey)
				Expect(ok).To(BeFalse()) // Expect no successful retrieval
				Expect(data).To(BeNil()) // Expect no successful retrieval
			}
		}
	})
	It("should prevent unauthorized access by predicting UUIDs for common filenames", func() {
		_, _ = client.InitUser("Diana", "dianapass")
		commonFilenames := []string{"document", "notes", "private"}

		for _, filename := range commonFilenames {
			attackStorageKey, _, _, _ := generateAllKeys(filename, "someRandomGuess", "Diana")
			data, ok := userlib.DatastoreGet(attackStorageKey)
			Expect(ok).To(BeFalse()) // Expect no successful retrieval
			Expect(data).To(BeNil()) // Expect no successful retrieval
		}
	})
	It("should resist attacks based on username enumeration", func() {
		enumeratedUsernames := []string{"Eve", "Frank", "Grace"} // Assuming these usernames are obtained by an attacker

		for _, username := range enumeratedUsernames {
			attackStorageKey, _, _, _ := generateAllKeys("guessedFile", "someRandomGuess", username)
			data, ok := userlib.DatastoreGet(attackStorageKey)
			Expect(ok).To(BeFalse()) // Expect no successful retrieval
			Expect(data).To(BeNil())
		}
	})
	It("should resist fuzzing attacks", func() {
		for i := 0; i < 1000; i++ { // 1000 iterations as an example
			randomUsername := userlib.RandomBytes(10) // Random 10-byte username
			randomPassword := userlib.RandomBytes(10) // Random 10-byte password
			randomFilename := userlib.RandomBytes(10) // Random 10-byte filename

			attackStorageKey, _, _, _ := generateAllKeys(string(randomFilename), string(randomPassword), string(randomUsername))
			data, ok := userlib.DatastoreGet(attackStorageKey)
			Expect(ok).To(BeFalse()) // Expect no successful retrieval
			Expect(data).To(BeNil())
		}
	})
	It("should resist unauthorized access exploiting generateAllKeys", func() {
		alice, _ = client.InitUser("Alice", alicePassword)
		_ = alice.StoreFile(aliceFile, []byte("Alice's secret data"))

		// Try to exploit the generateAllKeys helper function
		attackStorageKey, _, _, _ := generateAllKeys(aliceFile, "wrongPassword", "Alice")
		data, ok := userlib.DatastoreGet(attackStorageKey)
		Expect(ok).To(BeFalse()) // Expect no successful retrieval
		Expect(data).To(BeNil()) // Expect no successful retrieval
	})

	It("should resist unauthorized access exploiting simpleConcat", func() {
		bob, _ = client.InitUser("Bob", bobPassword)
		_ = bob.StoreFile(bobFile, []byte("Bob's secret data"))

		// Try to exploit the simpleConcat helper function
		attackStorageKey := simpleConcat("Bob", "wrongPassword", bobFile)
		data, ok := userlib.DatastoreGet(attackStorageKey)
		Expect(ok).To(BeFalse()) // Expect no successful retrieval
		Expect(data).To(BeNil())
	})

	It("should resist unauthorized access exploiting pbkdfNoSalt", func() {
		charles, _ = client.InitUser("Charles", "charlesPassword")
		_ = charles.StoreFile(charlesFile, []byte("Charles's secret data"))

		// Try to exploit the pbkdfNoSalt helper function
		attackStorageKey := pbkdfNoSalt("wrongPassword")
		data, ok := userlib.DatastoreGet(attackStorageKey)
		Expect(ok).To(BeFalse()) // Expect no successful retrieval
		Expect(data).To(BeNil())
	})

	It("should resist unauthorized access exploiting deriveWithCreationDate", func() {
		david, _ = client.InitUser("David", "davidPassword")
		_ = david.StoreFile(dorisFile, []byte("David's secret data"))

		// Try to exploit the deriveWithCreationDate helper function
		attackStorageKey := deriveWithCreationDate("David", "wrongPassword", dorisFile, "wrongDate")
		data, ok := userlib.DatastoreGet(attackStorageKey)
		Expect(ok).To(BeFalse()) // Expect no successful retrieval
		Expect(data).To(BeNil())
	})

	It("should resist unauthorized access exploiting constantSalted", func() {
		eve, _ = client.InitUser("Eve", "evePassword")
		_ = eve.StoreFile(eveFile, []byte("Eve's secret data"))

		// Try to exploit the constantSalted helper function
		attackStorageKey := constantSalted("Eve", "wrongPassword", eveFile)
		data, ok := userlib.DatastoreGet(attackStorageKey)
		Expect(ok).To(BeFalse()) // Expect no successful retrieval
		Expect(data).To(BeNil())
	})

	It("should resist unauthorized access exploiting md5Derived", func() {
		frank, _ = client.InitUser("Frank", "frankPassword")
		_ = frank.StoreFile(frankFile, []byte("Frank's secret data"))

		// Try to exploit the md5Derived helper function
		attackStorageKey := md5Derived("Frank", "wrongPassword", frankFile)
		data, ok := userlib.DatastoreGet(attackStorageKey)
		Expect(ok).To(BeFalse()) // Expect no successful retrieval
		Expect(data).To(BeNil())
	})

	// Multi-session testing to simulate attack from different devices
	It("should resist multi-session unauthorized access exploiting generateAllKeys", func() {
		grace, _ = client.InitUser("Grace", "gracePassword")
		graceDesktop, _ := client.GetUser("Grace", "gracePassword")
		_ = grace.StoreFile(graceFile, []byte("Grace's secret data"))
		err = graceDesktop.AppendToFile(graceFile, []byte("Grace's secret data"))
		content, err := graceDesktop.LoadFile(graceFile)
		Expect(err).To(BeNil())
		Expect(content).To(Equal([]byte("Grace's secret dataGrace's secret data")))

		// Try to exploit the generateAllKeys helper function from another device
		attackStorageKey, _, _, _ := generateAllKeys(graceFile, "wrongPassword", "Grace")
		data, ok := userlib.DatastoreGet(attackStorageKey)
		Expect(ok).To(BeFalse()) // Expect no successful retrieval
		Expect(data).To(BeEmpty())
	})
	It("should resist unauthorized file overwrite exploiting simpleConcat", func() {
		horace, _ = client.InitUser("Horace", "horacePassword")
		_ = horace.StoreFile(horaceFile, []byte("Horace's secret data"))

		// Try to exploit the simpleConcat helper function to overwrite data
		attackStorageKey := simpleConcat("Horace", "wrongPassword", horaceFile)
		userlib.DatastoreSet(attackStorageKey, []byte("Malicious data"))
		data, _ := horace.LoadFile(horaceFile)
		Expect(data).NotTo(Equal([]byte("Malicious data")))
	})

	It("should resist unauthorized file append exploiting pbkdfNoSalt", func() {
		ira, _ = client.InitUser("Ira", "iraPassword")
		_ = ira.StoreFile(iraFile, []byte("Ira's initial data"))

		// Try to exploit the pbkdfNoSalt helper function to append data
		attackStorageKey := pbkdfNoSalt("wrongPassword")
		originalData, _ := ira.LoadFile(iraFile)
		data, _ := userlib.DatastoreGet(attackStorageKey)
		userlib.DatastoreSet(attackStorageKey, append([]byte("Malicious append"), data...))
		appendedData, err := ira.LoadFile(iraFile)
		Expect(err).To(BeNil())
		Expect(appendedData).To(Equal(originalData))

		attackStorageKey = pbkdfNoSalt("iraPassword")
		originalData, _ = ira.LoadFile(iraFile)
		data, _ = userlib.DatastoreGet(attackStorageKey)
		userlib.DatastoreSet(attackStorageKey, append([]byte("Malicious append"), data...))
		appendedData, err = ira.LoadFile(iraFile)
		Expect(err).To(BeNil())
		Expect(appendedData).To(Equal(originalData))

		attackStorageKey, _, _, _ = generateAllKeys(iraFile, "iraPassword", "Ira")
		originalData, _ = ira.LoadFile(iraFile)
		data, _ = userlib.DatastoreGet(attackStorageKey)
		userlib.DatastoreSet(attackStorageKey, append(data, []byte("Malicious append")...))
		appendedData, err = ira.LoadFile(iraFile)
		Expect(err).ToNot(BeNil())
		Expect(appendedData).ToNot(Equal(originalData))
	})

	It("should prevent filename leakage exploiting deriveWithCreationDate", func() {
		// Simulate a scenario where an attacker tries to guess filenames by changing the date
		// and observing if any valid storage key is derived.
		david, _ = client.InitUser("David", "davidPassword")
		_ = david.StoreFile(dorisFile, []byte("David's secret data"))

		attackStorageKey := deriveWithCreationDate("David", "davidPassword", dorisFile, "01/01/2021")
		_, ok := userlib.DatastoreGet(attackStorageKey)
		Expect(ok).To(BeFalse())
	})

	It("should resist replay attacks exploiting constantSalted", func() {
		// Simulate a scenario where an attacker captures an old version of the data
		// and tries to replay it to trick the system.
		eve, _ = client.InitUser("Eve", "evePassword")
		_ = eve.StoreFile(eveFile, []byte("Eve's version 1 data"))

		// Capture the old data
		attackStorageKey := constantSalted("Eve", "evePassword", eveFile)
		oldData, _ := userlib.DatastoreGet(attackStorageKey)

		// Now, Eve updates her file
		_ = eve.StoreFile(eveFile, []byte("Eve's version 2 data"))

		// Attacker replays old data
		userlib.DatastoreSet(attackStorageKey, oldData)

		// The system should resist the replay attack and still show the new data
		data, _ := eve.LoadFile(eveFile)
		Expect(data).To(Equal([]byte("Eve's version 2 data")))
	})

	It("should handle multiple invitations for the same file", func() {
		_, err := client.InitUser("Alice", alicePassword)
		_, err = client.InitUser("Alice", alicePassword)
		Expect(err).To(HaveOccurred())
		_, err = client.InitUser("", "password")
		Expect(err).To(HaveOccurred())
		_, err = client.InitUser("Bob", "")
		err = alice.StoreFile("edgeCaseFile", []byte(""))
		Expect(err).ToNot(HaveOccurred())
		err = alice.StoreFile("", []byte("content"))
		Expect(err).ToNot(HaveOccurred())
		err = alice.StoreFile("filen@me", []byte("content"))
		Expect(err).ToNot(HaveOccurred())
		err = alice.StoreFile(aliceFile, []byte("new content"))
		Expect(err).ToNot(HaveOccurred())
		data, _ := alice.LoadFile(aliceFile)
		Expect(data).To(Equal([]byte("new content")))
		_, err = alice.LoadFile("nonExistentFile")
		Expect(err).To(HaveOccurred())
		err = alice.AppendToFile("nonExistentFile", []byte("append data"))
		Expect(err).To(HaveOccurred())
		err = alice.AppendToFile("nonExistentFile", []byte("append data"))
		Expect(err).To(HaveOccurred())
		err = alice.AppendToFile(aliceFile, []byte(""))
		Expect(err).ToNot(HaveOccurred())
		_, err = alice.CreateInvitation("nonExistentFile", "Bob")
		Expect(err).To(HaveOccurred())
		invite1, _ := alice.CreateInvitation(aliceFile, "Bob")
		invite2, err := alice.CreateInvitation(aliceFile, "Bob")
		_ = invite1
		_ = invite2
		Expect(err).NotTo(BeNil())
		err = bob.AcceptInvitation("alice", invite1, "existingFilename")
		Expect(err).To(HaveOccurred())
		err = alice.RevokeAccess(aliceFile, "Charlie")
		Expect(err).To(HaveOccurred())
	})

})

var _ = Describe("RevokedUserAdversaryTests", func() {

	Context("Basic Revocation", func() {

		It("Should not allow a revoked user to access the file", func() {
			alice, _ := client.InitUser("Alice", "password1")
			bob, _ := client.InitUser("Bob", "password2")
			alice.StoreFile("file1", []byte("Secret content"))
			invite, _ := alice.CreateInvitation("file1", "Bob")
			bob.AcceptInvitation("Alice", invite, "file1_shared")

			// Alice revokes Bob's access
			alice.RevokeAccess("file1", "Bob")

			// Bob tries to retrieve the file after revocation
			_, err := bob.LoadFile("file1_shared")
			Expect(err).To(HaveOccurred()) // Expect an error since Bob's access was revoked
		})

	})

	Context("Tampering Post Revocation", func() {

		It("Should detect tampering by a revoked user", func() {
			alice, _ := client.InitUser("Alice", "password1")
			bob, _ := client.InitUser("Bob", "password2")
			alice.StoreFile("file1", []byte("Original content"))
			invite, _ := alice.CreateInvitation("file1", "Bob")
			bob.AcceptInvitation("Alice", invite, "file1_shared")

			// Alice revokes Bob's access
			alice.RevokeAccess("file1", "Bob")

			// Bob turns malicious and tampers with the datastore
			for UUID, _ := range userlib.DatastoreGetMap() {
				tamperedData := []byte("Malicious content")
				userlib.DatastoreSet(UUID, tamperedData)
			}

			// Alice tries to retrieve the file
			content, err := alice.LoadFile("file1")
			Expect(err).To(HaveOccurred())
			Expect(content).NotTo(Equal([]byte("Original content"))) // Expect the content to be tampered
		})

	})

	Context("Datastore Interaction by Revoked User", func() {

		It("Should ensure data remains confidential even if a revoked user accesses the datastore", func() {
			alice, _ := client.InitUser("Alice", "password1")
			bob, _ := client.InitUser("Bob", "password2")
			alice.StoreFile("file1", []byte("Confidential content"))
			invite, _ := alice.CreateInvitation("file1", "Bob")
			bob.AcceptInvitation("Alice", invite, "file1_shared")

			// Alice revokes Bob's access
			alice.RevokeAccess("file1", "Bob")

			// Bob tries to directly fetch the data from the datastore
			for _, data := range userlib.DatastoreGetMap() {
				// Check if the raw data is not equal to the original content
				Expect(data).NotTo(Equal([]byte("Confidential content")))
			}
		})

	})

})
var _ = Describe("ComplexRevocationTests", func() {

	Context("Multiple Users and Files", func() {

		It("Should handle revocation across multiple users and files correctly", func() {
			// Initialize 10 users
			users := make([]*client.User, 10)
			for i := 0; i < 10; i++ {
				users[i], _ = client.InitUser(fmt.Sprintf("User%d", i+1), "password")
			}

			// User1 stores 20 files
			for i := 0; i < 20; i++ {
				users[0].StoreFile(fmt.Sprintf("file%d", i+1), []byte(fmt.Sprintf("Content of file%d", i+1)))
			}

			// User1 shares each file with all other users
			for i := 0; i < 20; i++ {
				for j := 1; j < 10; j++ {
					invite, _ := users[0].CreateInvitation(fmt.Sprintf("file%d", i+1), fmt.Sprintf("User%d", j+1))
					users[j].AcceptInvitation(fmt.Sprintf("User1"), invite, fmt.Sprintf("file%d_shared", i+1))
				}
			}

			// Each user tries to access each file and should succeed
			for i := 0; i < 20; i++ {
				for j := 1; j < 10; j++ {
					_, err := users[j].LoadFile(fmt.Sprintf("file%d_shared", i+1))
					Expect(err).ToNot(HaveOccurred())
				}
			}

			// User1 revokes User2's access to all files
			for i := 0; i < 20; i++ {
				users[0].RevokeAccess(fmt.Sprintf("file%d", i+1), "User2")
			}

			// User2 tries to access each file and should fail
			for i := 0; i < 20; i++ {
				_, err := users[1].LoadFile(fmt.Sprintf("file%d_shared", i+1))
				Expect(err).To(HaveOccurred())
			}

			// User2 (revoked user) turns malicious and tampers with the datastore
			for UUID, _ := range userlib.DatastoreGetMap() {
				tamperedData := []byte("Malicious content by User2")
				userlib.DatastoreSet(UUID, tamperedData)
			}

			// User1 tries to retrieve the files and should detect tampering
			for i := 0; i < 20; i++ {
				_, err := users[0].LoadFile(fmt.Sprintf("file%d", i+1))
				Expect(err).To(HaveOccurred())
			}
		})

	})

})
var _ = Describe("More Flags", func() {

})

func generateAllKeys(filename string, password string, username string) (result uuid.UUID, encryptionKey []byte,
	hmacKey []byte, err error) {
	hexEncoded := hex.EncodeToString([]byte(username))
	hexDecoded, err := hex.DecodeString(hexEncoded)
	hexDecodedPassword, err := hex.DecodeString(hex.EncodeToString([]byte(password)))
	filename = hex.EncodeToString([]byte(filename))
	PWHash := userlib.Argon2Key(hexDecodedPassword, hexDecoded, 64)

	storageKey, err := userlib.HashKDF(PWHash[48:], []byte(filename))
	if err != nil {
		return uuid.Nil, nil, nil, errors.New("generateFileKey: Unable to Generate UUID")
	}
	result, err = uuid.FromBytes(storageKey[:16])
	filename = hex.EncodeToString([]byte(filename))

	encryptionKey, err = userlib.HashKDF(PWHash[16:32],
		[]byte(filename))
	if err != nil {
		return uuid.Nil, nil, nil, errors.New("generateFileKey: Unable to Generate Encryption Key")
	}

	hmacKey, err = userlib.HashKDF(PWHash[32:48], []byte("hmacFile"))
	if err != nil {
		return uuid.Nil, nil, nil, errors.New("generateFileKey: Unable to Generate PreHash")
	}

	if err != nil {
		return uuid.Nil, nil, nil, errors.New("generateFileKey: Unable to Generate storageKey")
	}

	return result, encryptionKey, hmacKey, err
}
func simpleConcat(username string, password string, filename string) uuid.UUID {
	combined := username + password + filename
	hashed := userlib.Hash([]byte(combined))
	ID, err := uuid.FromBytes(hashed[:16])
	if err != nil {
		return uuid.Nil
	}
	return ID
}

func pbkdfNoSalt(password string) uuid.UUID {
	key, err := userlib.HashKDF([]byte(password), nil)
	if err != nil {
		return uuid.Nil
	}
	ID, err := uuid.FromBytes(key[:16])
	if err != nil {
		return uuid.Nil
	}
	return ID
}

func deriveWithCreationDate(username string, password string, filename string, date string) uuid.UUID {
	combined := username + password + filename + date
	hashed := userlib.Hash([]byte(combined))
	ID, err := uuid.FromBytes(hashed[:16])
	if err != nil {
		return uuid.Nil
	}
	return ID
}

func constantSalted(username string, password string, filename string) uuid.UUID {
	constantSalt := "SYSTEM_SALT_123456"
	combined := username + password + filename + constantSalt
	hashed := userlib.Hash([]byte(combined))
	ID, err := uuid.FromBytes(hashed[:16])
	if err != nil {
		return uuid.Nil
	}
	return ID
}

func md5Derived(username string, password string, filename string) uuid.UUID {
	data := []byte(username + password + filename)
	md5Hashed := userlib.Hash(data)
	ID, err := uuid.FromBytes(md5Hashed[:16])
	if err != nil {
		return uuid.Nil
	}
	return ID
}

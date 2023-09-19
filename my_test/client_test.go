package client_test_new_test

// You MUST NOT change these default imports.  ANY additional imports may
// break the autograder and everyone will be sad.

import (
	"encoding/hex"
	"errors"

	// Some imports use an underscore to prevent the compiler from complaining
	// about unused imports.
	_ "encoding/hex"
	_ "errors"
	"fmt"
	"github.com/google/uuid"
	_ "strconv"
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
	RegisterFailHandler(Fail)
	RunSpecs(t, "Client Tests")
}

// ================================================
// Global Variables (feel free to add more!)
// ================================================
const defaultPassword = "password"
const emptyString = ""
const contentOne = "Bitcoin is Nick's favorite "
const contentTwo = "digital "
const contentThree = "cryptocurrency!"

// ================================================
// Describe(...) blocks help you organize your tests
// into functional categories. They can be nested into
// a tree-like structure.
// ================================================

var _ = Describe("Client Tests", func() {
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
		// This runs before each test within this Describe block (including nested tests).
		// Here, we reset the state of Datastore and Keystore so that tests do not interfere with each other.
		// We also initialize
		userlib.DatastoreClear()
		userlib.KeystoreClear()
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

// +build darwin

package main

// See https://developer.apple.com/library/ios/documentation/Security/Reference/keychainservices/index.html for the APIs used below.

// Also see https://developer.apple.com/library/ios/documentation/Security/Conceptual/keychainServConcepts/01introduction/introduction.html .

/*
#cgo CFLAGS: -mmacosx-version-min=10.6 -D__MAC_OS_X_VERSION_MAX_ALLOWED=1080
#cgo LDFLAGS: -framework Security -framework CoreFoundation

#include <errno.h>
#include <sys/sysctl.h>
#include <CoreFoundation/CoreFoundation.h>
#include <CoreFoundation/CFBase.h>
#include <Security/Security.h>

OSStatus CreateCertAndIdentity(SecCertificateRef certificate, SecIdentityRef *identity) {
    OSStatus ret = noErr;
    ret = SecIdentityCreateWithCertificate(NULL, certificate, identity);
    if (ret != noErr) {
       return ret;
    }
    return noErr;
}

OSStatus SetPreferredIdentity(SecIdentityRef identity, CFStringRef name) {
		OSStatus ret = noErr;
		ret = SecIdentitySetPreferred(identity, name, NULL);
		if (ret != noErr) {
			 return ret;
		}
		return noErr;
}
*/
import "C"
import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"time"
)

// Error defines keychain errors
type Error int

var (
	// ErrorUnimplemented corresponds to errSecUnimplemented result code
	ErrorUnimplemented = Error(C.errSecUnimplemented)
	// ErrorParam corresponds to errSecParam result code
	ErrorParam = Error(C.errSecParam)
	// ErrorAllocate corresponds to errSecAllocate result code
	ErrorAllocate = Error(C.errSecAllocate)
	// ErrorNotAvailable corresponds to errSecNotAvailable result code
	ErrorNotAvailable = Error(C.errSecNotAvailable)
	// ErrorAuthFailed corresponds to errSecAuthFailed result code
	ErrorAuthFailed = Error(C.errSecAuthFailed)
	// ErrorDuplicateItem corresponds to errSecDuplicateItem result code
	ErrorDuplicateItem = Error(C.errSecDuplicateItem)
	// ErrorItemNotFound corresponds to errSecItemNotFound result code
	ErrorItemNotFound = Error(C.errSecItemNotFound)
	// ErrorInteractionNotAllowed corresponds to errSecInteractionNotAllowed result code
	ErrorInteractionNotAllowed = Error(C.errSecInteractionNotAllowed)
	// ErrorDecode corresponds to errSecDecode result code
	ErrorDecode = Error(C.errSecDecode)
	// ErrorNoSuchKeychain corresponds to errSecNoSuchKeychain result code
	ErrorNoSuchKeychain = Error(C.errSecNoSuchKeychain)
	// ErrorNoSuchAttribute corresponds to errSecNoSuchAttr result code
	ErrorNoSuchAttribute = Error(C.errSecNoSuchAttr)
)

func checkError(errCode C.OSStatus) error {
	if errCode == C.errSecSuccess {
		return nil
	}
	return Error(errCode)
}

func (k Error) Error() string {
	var msg string
	// SecCopyErrorMessageString is only available on OSX, so derive manually.
	switch k {
	case ErrorItemNotFound:
		msg = fmt.Sprintf("Item not found (%d)", k)
	case ErrorDuplicateItem:
		msg = fmt.Sprintf("Duplicate item (%d)", k)
	case ErrorParam:
		msg = fmt.Sprintf("One or more parameters passed to the function were not valid (%d)", k)
	case ErrorNoSuchKeychain:
		msg = fmt.Sprintf("No such keychain (%d)", k)
	case -25243:
		msg = fmt.Sprintf("No access for item (%d)", k)
	default:
		msg = fmt.Sprintf("Keychain Error (%d)", k)
	}
	return msg
}

// SecClass is the items class code
type SecClass int
type SecValueRef bool
type SecReturnRef string

// Keychain Item Classes
const (
	/*
		kSecClassGenericPassword item attributes:
		 kSecAttrAccess (OS X only)
		 kSecAttrAccessGroup (iOS; also OS X if kSecAttrSynchronizable specified)
		 kSecAttrAccessible (iOS; also OS X if kSecAttrSynchronizable specified)
		 kSecAttrAccount
		 kSecAttrService
	*/
	SecClassGenericPassword SecClass = (1 << iota)

	/*
		kSecClassCertificate item attributes:
			kSecAttrCertificateType
			kSecAttrCertificateEncoding
			kSecAttrLabel
			kSecAttrSubject
			kSecAttrIssuer
			kSecAttrSerialNumber
			kSecAttrSubjectKeyID
			kSecAttrPublicKeyHash
	*/
	SecClassCertificate SecClass = (1 << iota)

	/*
		kSecClassKey item attributes:
			kSecAttrAccess (OS X only)
			kSecAttrAccessGroup (iOS only)
			kSecAttrAccessible (iOS only)
			kSecAttrKeyClass
			kSecAttrLabel
			kSecAttrApplicationLabel
			kSecAttrIsPermanent
			kSecAttrApplicationTag
			kSecAttrKeyType
			kSecAttrPRF
			kSecAttrSalt
			kSecAttrRounds
			kSecAttrKeySizeInBits
			kSecAttrEffectiveKeySize
			kSecAttrCanEncrypt
			kSecAttrCanDecrypt
			kSecAttrCanDerive
			kSecAttrCanSign
			kSecAttrCanVerify
			kSecAttrCanWrap
			kSecAttrCanUnwrap

			Note that the attributes kSecAttrCan* describe attributes of the
			key itself at relatively high level. Some of these attributes are
			mathematical -- for example, a DSA key cannot encrypt. Others are
			key-level policy issues -- for example, it is good cryptographic
			hygiene to use an RSA key either for encryption or signing but not
			both. Compare these to the certificate-level policy values in
			SecPolicy.h.
	*/
	SecClassKey SecClass = (1 << iota)

	/*
		kSecClassIdentity item attributes:
			Since an identity is the combination of a private key and a
			certificate, this class shares attributes of both kSecClassKey and
			kSecClassCertificate.
	*/
	SecClassIdentity SecClass = (1 << iota)
)

const (
	/*
		As defined in cssmtype.h
			AddItem needs these values as CFStrings, but passing them directly
			causes an invalid pc panic and an Unsupported value type: main._Ctype_CFStringRef
			for the kSecAttrKeyType. To solve this problem, we create them as strings
			and cast them to CFString in the dictionary
	*/

	// SecAttrKeyTypeRSA from cssmtype, CSSM_ALGID_RSA
	SecAttrKeyTypeRSA = "42"

	// SecAttrKeyTypeEC from cssmtype, CSSM_ALGID_ECDSA
	SecAttrKeyTypeEC = "73"
)

// SecClassClassKey is the key type for SecClass
var SecClassClassKey = attrKey(C.CFTypeRef(C.kSecClass))

// SecValueRef is the key type for SecClass
var SecValueRefKey = attrKey(C.CFTypeRef(C.kSecValueRef))

// SecReturnRef is the key type for SecClass
var SecReturnRefKey = attrKey(C.CFTypeRef(C.kSecReturnRef))

var secClassTypeRef = map[SecClass]C.CFTypeRef{
	SecClassGenericPassword: C.CFTypeRef(C.kSecClassGenericPassword),
	SecClassCertificate:     C.CFTypeRef(C.kSecClassCertificate),
	SecClassKey:             C.CFTypeRef(C.kSecClassKey),
	SecClassIdentity:        C.CFTypeRef(C.kSecClassIdentity),
}

var (
	// ServiceKey is for kSecAttrService
	ServiceKey = attrKey(C.CFTypeRef(C.kSecAttrService))
	// LabelKey is for kSecAttrLabel
	LabelKey = attrKey(C.CFTypeRef(C.kSecAttrLabel))
	// AccountKey is for kSecAttrAccount
	AccountKey = attrKey(C.CFTypeRef(C.kSecAttrAccount))
	// AccessGroupKey is for kSecAttrAccessGroup
	AccessGroupKey = attrKey(C.CFTypeRef(C.kSecAttrAccessGroup))
	// DataKey is for kSecValueData
	DataKey = attrKey(C.CFTypeRef(C.kSecValueData))
	// DescriptionKey is for kSecAttrDescription
	DescriptionKey = attrKey(C.CFTypeRef(C.kSecAttrDescription))
	// SubjectKey is for kSecAttrSubject
	SubjectKey = attrKey(C.CFTypeRef(C.kSecAttrSubject))
	// IssuerKey is for kSecAttrSubject
	IssuerKey = attrKey(C.CFTypeRef(C.kSecAttrIssuer))
	// SerialNumberKey is for kSecAttrSerialNumber
	SerialNumberKey = attrKey(C.CFTypeRef(C.kSecAttrSerialNumber))
	// PublicKeyHashKey is for kSecAttrPublicKeyHash
	PublicKeyHashKey = attrKey(C.CFTypeRef(C.kSecAttrPublicKeyHash))
	// ApplicationTagKey is for kSecAttrApplicationTag
	ApplicationTagKey = attrKey(C.CFTypeRef(C.kSecAttrApplicationTag))
	// KeyTypeKey is for kSecAttrKeyType
	KeyTypeKey = attrKey(C.CFTypeRef(C.kSecAttrKeyType))
	// KeySizeInBitsKey is for kSecAttrKeySizeInBits
	KeySizeInBitsKey = attrKey(C.CFTypeRef(C.kSecAttrKeySizeInBits))
	// IsPermanentKey is for kSecAttrIsPermanent
	IsPermanentKey = attrKey(C.CFTypeRef(C.kSecAttrIsPermanent))
	// PrivateKeyAttrsKey is for kSecPrivateKeyAttrs
	PrivateKeyAttrsKey = attrKey(C.CFTypeRef(C.kSecPrivateKeyAttrs))
	// PublicKeyAttrsKey is for kSecPublicKeyAttrs
	PublicKeyAttrsKey = attrKey(C.CFTypeRef(C.kSecPublicKeyAttrs))
	// IsExtractableKey is for kSecAttrIsExtractable
	IsExtractableKey = attrKey(C.CFTypeRef(C.kSecAttrIsExtractable))
	// KeyClassKey is for kSecAttrKeyClass
	KeyClassKey = attrKey(C.CFTypeRef(C.kSecAttrKeyClass))
)

// Synchronizable is the items synchronizable status
type Synchronizable int

const (
	// SynchronizableDefault is the default setting
	SynchronizableDefault Synchronizable = 0
	// SynchronizableAny is for kSecAttrSynchronizableAny
	SynchronizableAny = 1
	// SynchronizableYes enables synchronization
	SynchronizableYes = 2
	// SynchronizableNo disables synchronization
	SynchronizableNo = 3
)

// SynchronizableKey is the key type for Synchronizable
var SynchronizableKey = attrKey(C.CFTypeRef(C.kSecAttrSynchronizable))
var syncTypeRef = map[Synchronizable]C.CFTypeRef{
	SynchronizableAny: C.CFTypeRef(C.kSecAttrSynchronizableAny),
	SynchronizableYes: C.CFTypeRef(C.kCFBooleanTrue),
	SynchronizableNo:  C.CFTypeRef(C.kCFBooleanFalse),
}

// Accessible is the items accessibility
type Accessible int

const (
	// AccessibleDefault is the default
	AccessibleDefault Accessible = 0
	// AccessibleWhenUnlocked is when unlocked
	AccessibleWhenUnlocked = 1
	// AccessibleAfterFirstUnlock is after first unlock
	AccessibleAfterFirstUnlock = 2
	// AccessibleAlways is always
	AccessibleAlways = 3
	// AccessibleWhenPasscodeSetThisDeviceOnly is when passcode is set
	AccessibleWhenPasscodeSetThisDeviceOnly = 4
	// AccessibleWhenUnlockedThisDeviceOnly is when unlocked for this device only
	AccessibleWhenUnlockedThisDeviceOnly = 5
	// AccessibleAfterFirstUnlockThisDeviceOnly is after first unlock for this device only
	AccessibleAfterFirstUnlockThisDeviceOnly = 6
	// AccessibleAccessibleAlwaysThisDeviceOnly is always for this device only
	AccessibleAccessibleAlwaysThisDeviceOnly = 7
)

// MatchLimit is whether to limit results on query
type MatchLimit int

const (
	// MatchLimitDefault is the default
	MatchLimitDefault MatchLimit = 0
	// MatchLimitOne limits to one result
	MatchLimitOne = 1
	// MatchLimitAll is no limit
	MatchLimitAll = 2
)

// MatchLimitKey is key type for MatchLimit
var MatchLimitKey = attrKey(C.CFTypeRef(C.kSecMatchLimit))
var matchTypeRef = map[MatchLimit]C.CFTypeRef{
	MatchLimitOne: C.CFTypeRef(C.kSecMatchLimitOne),
	MatchLimitAll: C.CFTypeRef(C.kSecMatchLimitAll),
}

// ReturnAttributesKey is key type for kSecReturnAttributes
var ReturnAttributesKey = attrKey(C.CFTypeRef(C.kSecReturnAttributes))

// ReturnDataKey is key type for kSecReturnData
var ReturnDataKey = attrKey(C.CFTypeRef(C.kSecReturnData))

// ReturnRefKey is key type for kSecReturnRef
var ReturnRefKey = attrKey(C.CFTypeRef(C.kSecReturnRef))

// Item for adding, querying or deleting.
type Item struct {
	// Values can be string, []byte, Convertable or CFTypeRef (constant).
	attr map[string]interface{}
}

// SetSecClass sets the security class
func (k *Item) SetSecClass(sc SecClass) {
	k.attr[SecClassClassKey] = secClassTypeRef[sc]
}

// SetSecReturnRef sets the returned reference indicator
func (k *Item) SetSecReturnRef(sc bool) {
	k.attr[SecReturnRefKey] = sc
}

// SetSecValueRef sets the security class
func (k *Item) SetSecValueRef(sc interface{}) {
	k.attr[SecValueRefKey] = sc
}

// SetSecValueData sets the data class
func (k *Item) SetSecValueData(sc C.CFDataRef) {
	k.attr[DataKey] = sc
}

// SetString sets a string attibute for a string key
func (k *Item) SetString(key string, s string) {
	if s != "" {
		k.attr[key] = s
	} else {
		delete(k.attr, key)
	}
}

// SetService sets the service attribute
func (k *Item) SetService(s string) {
	k.SetString(ServiceKey, s)
}

// SetAccount sets the account attribute
func (k *Item) SetAccount(a string) {
	k.SetString(AccountKey, a)
}

// SetLabel sets the label attribute
func (k *Item) SetLabel(l string) {
	k.SetString(LabelKey, l)
}

// SetDescription sets the description attribute
func (k *Item) SetDescription(s string) {
	k.SetString(DescriptionKey, s)
}

// SetData sets the data attribute
func (k *Item) SetData(b []byte) {
	if b != nil {
		k.attr[DataKey] = b
	} else {
		delete(k.attr, DataKey)
	}
}

// SetAccessGroup sets the access group attribute
func (k *Item) SetAccessGroup(ag string) {
	k.SetString(AccessGroupKey, ag)
}

// SetApplicationTag sets the access group attribute
func (k *Item) SetApplicationTag(at string) {
	k.SetString(ApplicationTagKey, at)
}

// SetKeySizeInBits sets the access group attribute
func (k *Item) SetKeySizeInBits(size int) {
	k.SetString(KeySizeInBitsKey, fmt.Sprintf("%d", size))
}

// SetPrivateKeyAttrs sets the private key
func (k *Item) SetPrivateKeyAttrs(pk Item) {
	cfDict, _ := ConvertMapToCFDictionary(pk.attr)
	defer Release(C.CFTypeRef(cfDict))
	k.attr[PrivateKeyAttrsKey] = cfDict
}

// SetPublicKeyAttrs sets the public key
func (k *Item) SetPublicKeyAttrs(pk Item) {
	cfDict, _ := ConvertMapToCFDictionary(pk.attr)
	defer Release(C.CFTypeRef(cfDict))
	k.attr[PublicKeyAttrsKey] = cfDict
}

// SetIsPermanent sets the permenance key
func (k *Item) SetIsPermanent(b bool) {
	k.attr[IsPermanentKey] = b
}

// SetIsExtractable sets the extractable key
func (k *Item) SetIsExtractable(b bool) {
	k.attr[IsExtractableKey] = b
}

// SetKeyType sets the keytype
func (k *Item) SetKeyType(s string) {
	k.SetString(KeyTypeKey, s)
}

// SetKeyClass sets the key class (private, public or symetric)
func (k *Item) SetKeyClass(s C.CFStringRef) {
	k.attr[KeyClassKey] = C.CFTypeRef(s)
}

// SetSynchronizable sets the synchronizable attribute
func (k *Item) SetSynchronizable(sync Synchronizable) {
	if sync != SynchronizableDefault {
		k.attr[SynchronizableKey] = syncTypeRef[sync]
	} else {
		delete(k.attr, SynchronizableKey)
	}
}

// SetAccessible sets the accessible attribute
func (k *Item) SetAccessible(accessible Accessible) {
	if accessible != AccessibleDefault {
		k.attr[AccessibleKey] = accessibleTypeRef[accessible]
	} else {
		delete(k.attr, AccessibleKey)
	}
}

// SetMatchLimit sets the match limit
func (k *Item) SetMatchLimit(matchLimit MatchLimit) {
	if matchLimit != MatchLimitDefault {
		k.attr[MatchLimitKey] = matchTypeRef[matchLimit]
	} else {
		delete(k.attr, MatchLimitKey)
	}
}

// SetReturnAttributes sets the return value type on query
func (k *Item) SetReturnAttributes(b bool) {
	k.attr[ReturnAttributesKey] = b
}

// SetReturnData enables returning data on query
func (k *Item) SetReturnData(b bool) {
	k.attr[ReturnDataKey] = b
}

// SetReturnRef enables returning references on query
func (k *Item) SetReturnRef(b bool) {
	k.attr[ReturnRefKey] = b
}

// NewItem is a new empty keychain item
func NewItem() Item {
	return Item{make(map[string]interface{})}
}

// NewGenericPassword creates a generic password item with the default keychain. This is a convenience method.
func NewGenericPassword(service string, account string, label string, data []byte, accessGroup string) Item {
	item := NewItem()
	item.SetSecClass(SecClassGenericPassword)
	item.SetService(service)
	item.SetAccount(account)
	item.SetLabel(label)
	item.SetData(data)
	item.SetAccessGroup(accessGroup)
	return item
}

type SecIdent struct {
	Ref C.SecIdentityRef
}

// AssignIdentity will assign a SecIdentityRef to a named service requiring the identity
func (s *SecIdent) AssignIdentity(preferred []string) error {
	for _, pref := range preferred {
		str, err := StringToCFString(pref)
		if err != nil {
			return err
		}

		err = checkError(C.SetPreferredIdentity(s.Ref, str))
		if err != nil {
			return err
		}
	}
	return nil
}

// NewIdentityCertificate creates a new identity from the supplied certificate
func NewIdentityCertificate(certificate []byte) (*SecIdent, error) {
	var secident *SecIdent
	// Convert the certificate byte data to CFData
	certData, err := BytesToCFData(certificate)
	if err != nil {
		return secident, fmt.Errorf("Invalid certificate payload provided")
	}

	// Parse the certificate data
	myCertRef, err := C.SecCertificateCreateWithData(nil, C.CFDataRef(certData))
	if err != nil {
		return secident, fmt.Errorf("Unable to parse certificate payload")
	}

	// Add the certificate to the keychain
	dictionary := NewItem()
	dictionary.SetSecClass(SecClassCertificate)
	dictionary.SetSecReturnRef(true)
	dictionary.SetSecValueRef(myCertRef)

	// Create a new SecIdentity for inclusion later
	var myIdentityRef C.SecIdentityRef
	mySecRef := C.CFTypeRef(myIdentityRef)
	err = AddItemToChain(dictionary, &mySecRef)
	if err != nil {
		return secident, fmt.Errorf("Unable to add certificate to keychain: %s", err)
	}

	err = checkError(C.CreateCertAndIdentity(C.SecCertificateRef(myCertRef), &myIdentityRef))
	switch err {
	case ErrorItemNotFound:
		return secident, fmt.Errorf("This item requires a private key that has not be added to the keychain")
	case ErrorDuplicateItem:
		return secident, fmt.Errorf("This item already exists in the keychain")
	}

	if err != nil {
		return secident, fmt.Errorf("Unable to add create identity with certificate: %s", err)
	}

	secident.Ref = myIdentityRef
	return secident, nil
}

// AddKeyPair will create a new public and private key entry using the name parameter
func AddKeyPair(name string, privateKey []byte, keyType string) error {
	var keyType string
	if keyType != SecAttrKeyTypeEC && keyType != SecAttrKeyTypeRSA {
		return fmt.Errorf("Unsupported key type. Only RSA and EC private keys are supported.")
	}

	// Create new private key item
	privKeyItem := NewItem()
	privKeyItem.SetSecClass(SecClassKey)
	privKeyItem.SetKeyType(keyType)
	privKeyItem.SetApplicationTag(name)
	privKeyItem.SetData(privateKey)
	privKeyItem.SetKeyClass(C.kSecAttrKeyClassPrivate)
	err := AddItem(privKeyItem)
	if err != nil {
		return fmt.Errorf("Unable to add private key: %s with error: %s", name, err)
	}

	return nil
}

// AddItem adds a Item to a Keychain
func AddItem(item Item) error {
	cfDict, err := ConvertMapToCFDictionary(item.attr)
	if err != nil {
		return err
	}
	defer Release(C.CFTypeRef(cfDict))

	errCode := C.SecItemAdd(cfDict, nil)
	err = checkError(errCode)
	return err
}

// AddItemToChain adds a Item to a Keychain
func AddItemToChain(item Item, chain *C.CFTypeRef) error {
	cfDict, err := ConvertMapToCFDictionary(item.attr)
	if err != nil {
		return err
	}
	defer Release(C.CFTypeRef(cfDict))

	errCode := C.SecItemAdd(cfDict, chain)
	err = checkError(errCode)
	return err
}

// UpdateItem updates the queryItem with the parameters from updateItem
func UpdateItem(queryItem Item, updateItem Item) error {
	cfDict, err := ConvertMapToCFDictionary(queryItem.attr)
	if err != nil {
		return err
	}
	defer Release(C.CFTypeRef(cfDict))
	cfDictUpdate, err := ConvertMapToCFDictionary(updateItem.attr)
	if err != nil {
		return err
	}
	defer Release(C.CFTypeRef(cfDictUpdate))
	errCode := C.SecItemUpdate(cfDict, cfDictUpdate)
	err = checkError(errCode)
	return err
}

// QueryResult stores all possible results from queries.
// Not all fields are applicable all the time. Results depend on query.
type QueryResult struct {
	Service     string
	Account     string
	AccessGroup string
	Label       string
	Description string
	Data        []byte
}

// QueryItemRef returns query result as CFTypeRef. You must release it when you are done.
func QueryItemRef(item Item) (C.CFTypeRef, error) {
	cfDict, err := ConvertMapToCFDictionary(item.attr)
	if err != nil {
		return 0, err
	}
	defer Release(C.CFTypeRef(cfDict))

	var resultsRef C.CFTypeRef
	errCode := C.SecItemCopyMatching(cfDict, &resultsRef)
	if Error(errCode) == ErrorItemNotFound {
		return 0, nil
	}
	err = checkError(errCode)
	if err != nil {
		return 0, err
	}
	return resultsRef, nil
}

// QueryItem returns a list of query results.
func QueryItem(item Item) ([]QueryResult, error) {
	resultsRef, err := QueryItemRef(item)
	if err != nil {
		return nil, err
	}
	if resultsRef == 0 {
		return nil, nil
	}
	defer Release(resultsRef)

	results := make([]QueryResult, 0, 1)

	typeID := C.CFGetTypeID(resultsRef)
	if typeID == C.CFArrayGetTypeID() {
		arr := CFArrayToArray(C.CFArrayRef(resultsRef))
		for _, ref := range arr {
			elementTypeID := C.CFGetTypeID(ref)
			if elementTypeID == C.CFDictionaryGetTypeID() {
				item, err := convertResult(C.CFDictionaryRef(ref))
				if err != nil {
					return nil, err
				}
				results = append(results, *item)
			} else {
				return nil, fmt.Errorf("invalid result type (If you SetReturnRef(true) you should use QueryItemRef directly)")
			}
		}
	} else if typeID == C.CFDictionaryGetTypeID() {
		item, err := convertResult(C.CFDictionaryRef(resultsRef))
		if err != nil {
			return nil, err
		}
		results = append(results, *item)
	} else if typeID == C.CFDataGetTypeID() {
		b, err := CFDataToBytes(C.CFDataRef(resultsRef))
		if err != nil {
			return nil, err
		}
		item := QueryResult{Data: b}
		results = append(results, item)
	} else {
		return nil, fmt.Errorf("Invalid result type: %s", CFTypeDescription(resultsRef))
	}

	return results, nil
}

func attrKey(ref C.CFTypeRef) string {
	return CFStringToString(C.CFStringRef(ref))
}

func convertResult(d C.CFDictionaryRef) (*QueryResult, error) {
	m := CFDictionaryToMap(C.CFDictionaryRef(d))
	result := QueryResult{}
	for k, v := range m {
		switch attrKey(k) {
		case ServiceKey:
			result.Service = CFStringToString(C.CFStringRef(v))
		case AccountKey:
			result.Account = CFStringToString(C.CFStringRef(v))
		case AccessGroupKey:
			result.AccessGroup = CFStringToString(C.CFStringRef(v))
		case LabelKey:
			result.Label = CFStringToString(C.CFStringRef(v))
		case DescriptionKey:
			result.Description = CFStringToString(C.CFStringRef(v))
		case DataKey:
			b, err := CFDataToBytes(C.CFDataRef(v))
			if err != nil {
				return nil, err
			}
			result.Data = b
			// default:
			// fmt.Printf("Unhandled key in conversion: %v = %v\n", cfTypeValue(k), cfTypeValue(v))
		}
	}
	return &result, nil
}

// DeleteGenericPasswordItem removes a generic password item.
func DeleteGenericPasswordItem(service string, account string) error {
	item := NewItem()
	item.SetSecClass(SecClassGenericPassword)
	item.SetService(service)
	item.SetAccount(account)
	return DeleteItem(item)
}

// DeleteItem removes a Item
func DeleteItem(item Item) error {
	cfDict, err := ConvertMapToCFDictionary(item.attr)
	if err != nil {
		return err
	}
	defer Release(C.CFTypeRef(cfDict))

	errCode := C.SecItemDelete(cfDict)
	return checkError(errCode)
}

// GetAccountsForService is deprecated
func GetAccountsForService(service string) ([]string, error) {
	return GetGenericPasswordAccounts(service)
}

// GetGenericPasswordAccounts returns generic password accounts for service. This is a convenience method.
func GetGenericPasswordAccounts(service string) ([]string, error) {
	query := NewItem()
	query.SetSecClass(SecClassGenericPassword)
	query.SetService(service)
	query.SetMatchLimit(MatchLimitAll)
	query.SetReturnAttributes(true)
	results, err := QueryItem(query)
	if err != nil {
		return nil, err
	}

	accounts := make([]string, 0, len(results))
	for _, r := range results {
		accounts = append(accounts, r.Account)
	}

	return accounts, nil
}

// GetGenericPassword returns password data for service and account. This is a convenience method.
// If item is not found returns nil, nil.
func GetGenericPassword(service string, account string, label string, accessGroup string) ([]byte, error) {
	query := NewItem()
	query.SetSecClass(SecClassGenericPassword)
	query.SetService(service)
	query.SetAccount(account)
	query.SetLabel(label)
	query.SetAccessGroup(accessGroup)
	query.SetMatchLimit(MatchLimitOne)
	query.SetReturnData(true)
	results, err := QueryItem(query)
	if err != nil {
		return nil, err
	}
	if len(results) > 1 {
		return nil, fmt.Errorf("Too many results")
	}
	if len(results) == 1 {
		return results[0].Data, nil
	}
	return nil, nil
}

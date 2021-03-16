import 'package:fast_base58/fast_base58.dart';
import 'package:uuid/uuid.dart';
import 'package:cryptography/cryptography.dart' as c;

/// Represents the public key section specified in peer-did-method-spec
///   - https://identity.foundation/peer-did-method-spec/#publickey
///
/// The publicKey section of a peer DID document, in either stored or resolved form, is  as
/// you would expect from a reading of the DID spec. Peer DID docs MUST define all of their
/// internal and external keys in this  section;  although  the  DID  spec  permits  inline
/// definitions in the authentication and authorization sections of a  DID  doc,  this  DID
/// method disallows that option to simplify the possible permutations of a change fragment.
class PublicKey {

  /// Holds the public keys
  List<Key> _publicKeyInstance;

  /// Constructor
  ///   - Creates new instance of this class. After creation, use .addKey(...) method to
  ///     add new public key.
  PublicKey.create();

  /// Adds new public key to this instance
  ///
  /// Usage:
  ///   var keys = PublicKey.create()
  ///                     .addKey(Ed25519Key.createFromBase58EncodedPublicKey(...))
  ///                     .addKey(Ed25519Key.createFromBase58EncodedPublicKey(...))
  ///                     .addKey(Ed25519Key.createFromBase58EncodedPublicKey(...))
  PublicKey addKey(Key publicKeyInstance) { _publicKeyInstance.add(publicKeyInstance); return this; }

  /// Returns the list of public key.
  ///
  /// Sample output:
  /// [
  ///     {
  ///       "id": "H3C2AVvL",
  ///       "type": "Ed25519VerificationKey2018",
  ///       "controller": "#id",
  ///       "publicKeyBase58": "H3C2AVvLMv6gmMNam3uVAjZpfkcJCwDwnZn6z3wXmqPV"
  ///     },
  ///     ... so on
  /// ]
  List<Map> get list { var map = []; for(var publicKeyInstance in _publicKeyInstance) { map.add(publicKeyInstance.map); } return map; }
}

/// This abstract class represents a single public key. This is designed to have  different
/// implementations such as public key for Ed25519. The implementations of this abstract
/// class is to be consumed by the PublicKey instance.
abstract class Key {

  /// 8-character unique representation of public key across the did document.
  ///
  /// For example, if the key is defined with a publicKeyBase58 property value that  begins
  /// with H3C2AVvL, then its id would be H3C2AVvL; a key with a publicKeyHex property that
  /// begins with 02b97c30 would have an id of 02b97c30, and  a  key  with  a  publicKeyPem
  /// property that begins, after  its  -----BEGIN PUBLIC KEY  delimiter,  with  the  value
  /// izfrNTmQ, would have an id of izfrNTmQ.
  ///
  /// Sample:
  /// {
  ///     "id": "H3C2AVvL",
  ///      ...
  /// }
  String get id;

  /// Hashtag + id string
  String get hid => '#$id';

  /// Key type. This is defined by this abstract class' implementation.
  /// {
  ///     ...
  ///     "type": "Secp256k1VerificationKey2018",
  ///     ...
  /// }
  String get type;

  /// Just '#id' as seen in the peer did doc spec.
  /// {
  ///    ...
  ///    "controller": "#id",
  ///    ...
  /// }
  String get controller => '#id';

  /// Base58 representation of the public key. There are others such as publicKeyHex
  /// and publicKeyPem, but we only implemented base58 only.
  /// {
  ///     ...
  ///     "publicKeyBase58": "H3C2AVvLMv6gmMNam3uVAjZpfkcJCwDwnZn6z3wXmqPV"
  /// }
  String get publicKeyBase58;

  /// Returns map version of this public key:
  /// {
  ///     "id": "H3C2AVvL",
  ///     "type": "Ed25519VerificationKey2018",
  ///     "controller": "#id",
  ///     "publicKeyBase58": "H3C2AVvLMv6gmMNam3uVAjZpfkcJCwDwnZn6z3wXmqPV"
  /// }
  Map get map;

  /// Key's profile (private)
  AuthorizationProfile _profile;

  /// Returns the key's profile.
  ///
  /// As per implementation, every key has / may have profile that is to be used by rules
  /// as condition for granting specific privileges.
  ///
  /// To add role for this public key (Example code):
  /// // Assume that key is an instance of implementation of Key class
  /// key
  ///   .addRole(role: 'admin')                     // You may add single role
  ///   .addRole(roles: ['offline', 'biometrics'])  // Or list of roles
  ///
  /// With the given inputs above, this will be the JSON representation of this profile:
  /// {"key": "#02b97c30", "roles": ["admin", "offline", "biometrics"]}
  ///
  AuthorizationProfile get profile => _profile;

  /// Verifies a signed message using this public key.
  ///
  /// For usage, please refer to implementation.
  Future<bool> verify(String base58Message, String base58Signature);

  /// Add role for this public key. By default, all keys don't have role unless a role  has
  /// been added.
  ///
  /// Usage:
  ///   // Assume that key is an instance of implementation of Key class
  ///   key
  ///     .addRole(role: 'admin')                     // You may add single role
  ///     .addRole(roles: ['offline', 'biometrics'])  // Or list of roles
  Key addRole({String role, List<String> roles}) {

    // Creates new instance of authorization profile if _profile is not yet instantiated
    _profile = _profile == null ?? AuthorizationProfile.create(this);

    // Adds the single role
    if (role != null) _profile.addRole(role: role);

    // Adds multiple role
    if (roles != null) _profile.addRole(roles: roles);

    // Returns this instance for method chaining
    return this;
  }

  /// Remove all roles for this public key
  ///
  /// Usage:
  ///   // Assume that key is instance of implementation of key class
  ///   key.removeRoles()
  void removeRoles() { _profile = null; }
}

/// This class is Ed25519 implementation that has type of 'Ed25519VerificationKey2018'. The
/// instance of this class is to be consumed by PublicKey instance.
class Ed25519Key extends Key {

  c.PublicKey _publicKey;

  /// Constructor is disabled. Please use:
  ///   - createFromBytes()
  ///   - createFromBase58EncodedPublicKey
  Ed25519Key._constructor();

  /// Creates Ed25519PublicKey instance from public key bytes (List<int>)
  ///
  /// TODO: Sample usage
  static Ed25519Key createFromBytes(List<int> bytes) {

    // Creates Ed25519Key instance (calling the constructor)
    final instance = Ed25519Key._constructor();

    // Creates PublicKey instance from 'package:cryptography/cryptography.dart'
    instance._publicKey = c.PublicKey(bytes);

    // Returns our new instance
    return instance;
  }

  /// Creates Ed25519PublicKey instance from base58 encoded Ed25519 public key
  ///
  /// TODO: Sample usage
  static Ed25519Key createFromBase58EncodedPublicKey(String base58PublicKey) {

    // Creates Ed25519Key instance (calling the constructor)
    final instance = Ed25519Key._constructor();

    // Creates PublicKey instance from 'package:cryptography/cryptography.dart'
    instance._publicKey = c.PublicKey(Base58Decode(base58PublicKey));

    // Returns our new instance
    return instance;
  }

  /// 8-character unique representation of public key across the did document.
  ///
  /// For example, if the key is defined with a publicKeyBase58 property value that  begins
  /// with H3C2AVvL, then its id would be H3C2AVvL; a key with a publicKeyHex property that
  /// begins with 02b97c30 would have an id of 02b97c30, and  a  key  with  a  publicKeyPem
  /// property that begins, after  its  -----BEGIN PUBLIC KEY  delimiter,  with  the  value
  /// izfrNTmQ, would have an id of izfrNTmQ.
  ///
  /// Sample:
  /// {
  ///     "id": "H3C2AVvL",
  ///      ...
  /// }
  @override
  String get id => publicKeyBase58.substring(0, 7);

  /// Key type. This is defined by this abstract class' implementation.
  /// {
  ///     ...
  ///     "type": "Secp256k1VerificationKey2018",
  ///     ...
  /// }
  @override
  String get type => 'Ed25519VerificationKey2018';

  /// Just '#id' as seen in the peer did doc spec.
  /// {
  ///    ...
  ///    "controller": "#id",
  ///    ...
  /// }
  @override
  String get controller => '#id';

  /// Base58 representation of the public key. There are others such as publicKeyHex
  /// and publicKeyPem, but we only implemented base58 only.
  /// {
  ///     ...
  ///     "publicKeyBase58": "H3C2AVvLMv6gmMNam3uVAjZpfkcJCwDwnZn6z3wXmqPV"
  ///     ...
  /// }
  @override
  String get publicKeyBase58 => Base58Encode(_publicKey.bytes);

  /// Returns map version of this public key:
  /// {
  ///     "id": "H3C2AVvL",
  ///     "type": "Ed25519VerificationKey2018",
  ///     "controller": "#id",
  ///     "publicKeyBase58": "H3C2AVvLMv6gmMNam3uVAjZpfkcJCwDwnZn6z3wXmqPV"
  /// }
  @override
  Map get map => { 'id':  id, 'type': type, 'controller': controller, 'publicKeyBase58': publicKeyBase58 };

  /// Verifies a signed message using this public key.
  ///
  /// TODO: Write how this method is practically used.
  @override
  Future<bool> verify(String base58Message, String base58Signature) async => await c.ed25519.verify(Base58Decode(base58Message), c.Signature(Base58Decode(base58Signature), publicKey: _publicKey));
}


/// Represents authorization specified in peer-did-method-spec
///   - https://identity.foundation/peer-did-method-spec/#authorization
///
/// This class contains the authorization profile and authorization rules
///
/// Peer DID docs organize their authorization section into two lists. The first, profiles,
/// gives a trust profile for each key, as expressed by named roles the  key  holds.  These
/// named roles are arbitrary strings chosen by the implementer; since they are  only  used
/// to match against rules in the second list, their meaning in normal  language  does  not
/// need to be understood by a party wishing to support correct semantics.
///
/// This class when rendered as string should look like this as specified  in  the  peerdid
/// spec:
/// “authorization”: {
///     "profiles": [
///         {"key": "#Mv6gmMNa", "roles", ["edge"]},              // an "edge" key
///         {"key": "#izfrNTmQ", "roles", ["edge", "biometric"]}, // an "edge" and a "biometric" key
///         {"key": "#02b97c30", "roles", ["cloud"]},             // a "cloud" key
///         {"key": "#H3C2AVvL", "roles", ["offline"]},           // an "offline" key
///     ],
///     "rules": [
///         {
///             "grant": ["register"],
///             "when": {"id": "#Mv6gmMNa"},
///             "id": "7ac4c6be"
///         },
///         {
///             "grant": ["route", "authcrypt"],
///             "when": {"roles": "cloud"},
///             "id": "98c2c9cc"
///         },
///         {
///             "grant": ["authcrypt", "plaintext", "sign"],
///             "when": {"roles": "edge"},
///             "id": "e1e7d7bc"
///         },
///         {
///             "grant": ["key_admin", "se_admin", "rule_admin"],
///             "when": {
///                 "any": [{"roles": "offline"}, {"roles": "biometric"}],
///                 "n": 2
///             }
///             "id": "8586d26c"
///         }
///     ]
/// }
class Authorization {

  /// List of profiles object
  final List<AuthorizationProfile> _profiles = <AuthorizationProfile>[];

  /// List of rules object
  final List<AuthorizationRule> _rules = <AuthorizationRule>[];

  /// Constructor
  Authorization.create();

  /// Get all profiles from given privilege
  List<AuthorizationProfile> _getProfileFromPrivilege(String privilege) {

    // First: Get all conditions from given privilege
    final conditions = <Map>[];

    // Second: Get all roles from condition
    final roles = <String>[];

    // Third: Get all key ids from condition
    final key_ids = <String>[];

    // Loop through rules and search for conditions
    for (var rule in _rules) {

      // Check if rule is not granted by given privilege
      if (!rule.grants.contains(privilege)) continue;
    }
  }

  /// Get all keys from given profiles

  /// Returns all key instances that are granted with register privilege
  List<Key> getRegisterKey() {

    // Get all profile with register privilege
    // _getProfileFromPrivilege('register');

    // Get all keys with given profile
    // _getKeyFromProfile(['profile1', 'profile2', 'profile3']);
  }

  /// Returns all key instances that are granted with route privilege
  List<Key> getRouteKey() { throw UnimplementedError(); }

  /// Returns all key instances that are granted with authcrypt privilege
  List<Key> getAuthcryptKey() { throw UnimplementedError(); }

  /// Returns all key instances that are granted with plaintext privilege
  List<Key> getPlaintextKey() { throw UnimplementedError(); }

  /// Returns all key instances that are granted with sign privilege
  List<Key> getSignKey() { throw UnimplementedError(); }

  /// Returns all key instances that are granted with key_admin privilege
  List<Key> getKeyadminKey() { throw UnimplementedError(); }

  /// Returns all key instances that are granted with se_admin privilege
  List<Key> getSeadminKey() { throw UnimplementedError(); }

  /// Returns all key instances that are granted with rule_admin privilege
  List<Key> getRuleadminKey() { throw UnimplementedError(); }

  /// Returns all key instances that don't have 'revoke-implicit' for rotate.
  /// All keys have rotate privilege unless it's revoked explicitly through
  /// 'revoke-implicit'.
  List<Key> getRotateKey() { throw UnimplementedError(); }

  /// Add new authorization profile
  ///
  /// TODO: Write usage guide
  ///
  /// When rendered, it looks something like this as specified in the spec.
  /// "profiles": [
  ///     {"key": "#Mv6gmMNa", "roles": ["edge"]},              // an "edge" key
  ///     {"key": "#izfrNTmQ", "roles": ["edge", "biometric"]}, // an "edge" and a "biometric" key
  ///     {"key": "#02b97c30", "roles": ["cloud"]},             // a "cloud" key
  ///     {"key": "#H3C2AVvL", "roles": ["offline"]},           // an "offline" key
  /// ],
  Authorization addProfile(Key publicKeyInstance) {

    // Adds a new profile to list if the public key instance has profile
    if (publicKeyInstance.profile != null) _profiles.add(publicKeyInstance.profile);

    // Returns this instance for method chaining
    return this;
  }

  /// Add new authorization rule
  ///
  /// Usage:
  /// AuthorizationRules.create()
  ///   .addRule(AuthorizationRule.grant(...).when(...))
  ///   .addRule(AuthorizationRule.grant(...).when(...))
  ///   ...
  ///   .addRule(AuthorizationRule.grant(...).when(...));
  ///
  /// Or:
  /// AuthorizationRules.create().add(AuthorizationRule.fromMap(...));
  ///
  /// When rendered, it looks something like this as specified in the spec.
  /// "rules": [
  ///     {
  ///         "grant": ["register"],
  ///         "when": {"id": "#Mv6gmMNa"},
  ///         "id": "7ac4c6be"
  ///     },
  ///     {
  ///         "grant": ["route", "authcrypt"],
  ///         "when": {"roles": "cloud"},
  ///         "id": "98c2c9cc"
  ///     },
  ///     {
  ///         "grant": ["authcrypt", "plaintext", "sign"],
  ///         "when": {"roles": "edge"},
  ///         "id": "e1e7d7bc"
  ///     },
  ///     {
  ///         "grant": ["key_admin", "se_admin", "rule_admin"],
  ///         "when": {
  ///             "any": [{"roles": "offline"}, {"roles": "biometric"}],
  ///             "n": 2
  ///         }
  ///         "id": "8586d26c"
  ///     }
  /// ]
  Authorization addRule(AuthorizationRule rule) { _rules.add(rule); return this; }

  /// Returns the map version of this class
  Map get map { var list = []; for (var rule in _rules) { list.add(rule.map); } return { 'rules': list }; }
}

class AuthorizationProfile {

  /// Public key that is referenced upon creation of this class' instance.
  Key _publicKeyInstance;

  /// Profile roles. (private)
  final List<String> _roles = <String>[];

  /// Profile Key.
  ///   - This key refers to the public key's ID that is prefixed by hash symbol.
  ///
  /// "profiles": [
  ///     ...
  ///     {"key": "#Mv6gmMNa", ...}
  ///     ...
  /// ]
  String get key => _publicKeyInstance.hid;

  /// Profile roles.
  ///
  /// "profiles": [
  ///     ...
  ///     { ..., "roles", ["edge", "biometric"]},
  ///     ...
  /// ],
  List<String> get roles => _roles;

  /// Constructor
  ///   - Creates instance of Authorization profile.
  ///
  /// Usage:
  ///   // Assume that this is called inside the implementation of Key class.
  ///   AuthorizationProfile.create(this);
  AuthorizationProfile.create(Key publicKeyInstance) {

    // Sets the associated public key for this profile.
    _publicKeyInstance = publicKeyInstance;
  }

  void addRole({String role, List<String> roles}) {

    // Adds single role
    if (role != null) _roles.add(role);

    // Adds multiple role
    if (roles != null) _roles + roles;
  }
}


/// https://identity.foundation/peer-did-method-spec/#privilege-inventory
enum PrivilegeInventory {

  /// The holder of this privilege is allowed to register the DID  as  an  identifier  with
  /// another party. Exactly one key MUST hold this privilege in  the  genesis  version  of
  /// the DID doc. This inception key creates the DID and takes  custody  of  it  at  least
  /// until it can be exchanged with a peer. This  key  MUST  authenticate  with  the  peer
  /// during DID exchange; any other authentication MUST be rejected as  it  may  represent
  /// a different, otherwise-authorized key trying to exchange the DID in ways that diverge
  /// from its creator's intentions. After the DID has been registered once, no key  SHOULD
  /// hold this privilege unless/until it is registered again (e.g., in upgrading  pairwise
  /// to n-wise).
  register,

  /// The holder of this privilege is  allowed  to  receive  and  decrypt  DIDComm  forward
  /// messages encrypted for itself,  and  to  forward  the  contained  DIDComm  encryption
  /// envelope to another key. Holders of these keys thus become aware of  the  timing  and
  /// size of some incoming messages for the recipient (though not of the messages' senders
  /// or content). This privilege is required  and  appropriate  for  any  cloud  agent  or
  /// mediator that exposes a service endpoint on behalf of mobile devices or other  agents
  /// behind a firewall.
  route,

  /// The holder of this privilege is  allowed  to  create  messages  and  send  them  with
  /// authenticated encryption that reveals the identity associated with this  DID  to  the
  /// reciever. Most agents are likely to have this privilege, but one designed for passive
  /// reception only (e.g., on an IoT sensor) might have it removed; doing so would prevent
  /// a hacker from co-opting such a key into sending in a trusted way. Messages  that  are
  /// authcrypted by a key that lacks this privilege SHOULD be rejected as unauthorized.
  authcrypt,

  /// The holder of this privilege can see  plaintext  DIDComm  messages  intended  for  an
  /// identity owner engaged in a protocol . External parties sending to  the  owner  of  a
  /// given DIDDoc should multiplex encrypt for all keys that hold this  privilege,  except
  /// in special circumstances.
  plaintext,

  /// The holder of this privilege can  incur  non-repudiable  contractual  obligations  on
  /// behalf of the DID  subject.  This  may  actually  be  a  better  test  for  login  or
  /// authentication, in many cases, than whether  a  key  appears  in  the  authentication
  /// section of the DID doc; it depends on what trust is imputed after login.
  sign,

  /// The holder of this privilege can add or remove other  keys  from  a  peer  DID  doc's
  /// publicKey section, authentication section, or authorization.profiles list.  Typically
  /// this privilege is held only by very privileged keys, or by combinations of  keys,  to
  /// prevent hackers who co-opt  one  device  from  adding  new,  malicious  keys  to  the
  /// inventory. To guard against privilege escalation, it is  important  to  enforce  that
  /// entity adding the new key can only add grant privileges (add roles)  that  it  itself
  /// has. Also note that a key can remove itself from publicKey section, it does not  need
  /// the key_admin privilege. A real example would be when an existing device with  a  key
  /// in the DID doc gets damaged and the identity owner has no plans to replace it.
  key_admin,

  /// The holder of this privilege can add or remove items from a peer  DID  doc's  service
  /// section.
  se_admin,

  /// The holder of this  privilege  can  add  or  remove  rules  from  a  peer  DID  doc's
  /// authorization.rules list. Typically this privilege is held only  by  very  privileged
  /// keys, or by combinations of keys.
  rule_admin,

  /// The holder of this privilege can replace  its  associated  key  definition,  and  all
  /// references to that  key  throughout  a  DID  doc,  with  a  new  key  definition  and
  /// references, in a single delete-and-add operation. If key #2 has  this  privilege  and
  /// exercises it, the result is that key #2 is revoked  from  the  doc,  but  a  new  key
  /// (perhaps key #7) appears with exactly the same profile. This privilege is assumed  to
  /// be held by all keys unless rules specify otherwise. The construct revoke-implicit  is
  /// used to prevent keys from having implicit privileges. The example  below  shows  that
  /// the key id #H3C2AVvL is unable to replace its associated key definition.
  rotate
}

class AuthorizationRule {

  /// List of permitted privileges
  List<String> _grants;

  /// Condition(s) when to grant permission
  /// https://identity.foundation/peer-did-method-spec/#authorization
  Map _when;

  /// Unique ID for the rule. If not set, then this class will generate a uuidv4 string.
  /// AuthorizationRule.grant(...).when(...) will generate a uuidv4 string since it is used
  /// to create a new authorization rule from scratch.
  String _id;

  /// Constructor is disabled.
  AuthorizationRule._create();

  /// Refer to this document: https://identity.foundation/peer-did-method-spec/#authorization
  ///
  /// To put simply:
  /// final rule = AuthorizationRule.fromMap({
  ///   "grant": ["register"],
  ///   "when": {"id": "#Mv6gmMNa"},
  ///   "id": "7ac4c6be"
  /// });
  static AuthorizationRule fromMap(Map rule) {

    // Creates instance of AuthorizationRule
    final instance = AuthorizationRule._create();

    // Loops through grant and adds it to _grant list
    for (String grant in rule['grant']) {
      if (<String>['register', 'route', 'authcrypt', 'plaintext', 'sign', 'key_admin', 'se_admin', 'rule_admin', 'rotate'].contains(grant)) {
        instance._grants.add(grant);
      } else {
        throw Exception("Invalid authorization rule. Allowed rules: 'register', 'route', 'authcrypt', 'plaintext', 'sign', 'key_admin', 'se_admin', 'rule_admin', 'rotate'");
      }
    }

    // Sets the condition from where
    instance._when = rule['when'];

    // Either sets the specified ID from map, or generates uuidv4 if id does not exist.
    instance._id = rule.containsKey('id') ? rule['id'] : Uuid().v4();

    // Returns the instance
    return instance;
  }

  /// Use this method to create instance of rule.
  /// Sets the permissions to be granted. After using this method, immediately call .when()
  /// to set the condition.
  ///
  /// https://identity.foundation/peer-did-method-spec/#authorization
  ///
  /// Rule.grant([
  ///   PrivilegeInventory.key_admin,
  ///   PrivilegeInventory.se_admin,
  ///   PrivilegeInventory.rule_admin
  /// ]).when(...)
  static AuthorizationRule grant(List<PrivilegeInventory> grants) {
    final instance = AuthorizationRule._create();

    // Loops through grants and adds it to _grant list
    for (var grant in grants) {
      switch(grant) {
        case PrivilegeInventory.register: instance._grants.add('register'); break;
        case PrivilegeInventory.route: instance._grants.add('route'); break;
        case PrivilegeInventory.authcrypt: instance._grants.add('authcrypt'); break;
        case PrivilegeInventory.plaintext: instance._grants.add('plaintext'); break;
        case PrivilegeInventory.sign: instance._grants.add('sign'); break;
        case PrivilegeInventory.key_admin: instance._grants.add('key_admin'); break;
        case PrivilegeInventory.se_admin: instance._grants.add('se_admin'); break;
        case PrivilegeInventory.rule_admin: instance._grants.add('rule_admin'); break;
        case PrivilegeInventory.rotate: instance._grants.add('rotate'); break;
      }
    }

    // Returns the instance
    return instance;
  }

  /// Use this method after calling the static method grant. This method returns the
  /// instance of this class. This method sets the condition when to grant the said
  /// permissions specified in the PrivilegeInventory enum.
  ///
  /// https://identity.foundation/peer-did-method-spec/#authorization
  ///
  /// Rule.grant([
  ///   PrivilegeInventory.key_admin,
  ///   PrivilegeInventory.se_admin,
  ///   PrivilegeInventory.rule_admin
  /// ]).when(...)
  AuthorizationRule when(Map condition) { _when = condition; _id = Uuid().v4(); return this; }

  /// List of permitted privileges
  List<String> get grants => _grants;

  /// Condition(s) when to grant permission (when)
  /// https://identity.foundation/peer-did-method-spec/#authorization
  Map get conditions => _when;

  /// Returns the map version of this class
  Map get map => { 'grant': _grants, 'when': _when, 'id': _id };
}

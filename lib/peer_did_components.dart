import 'package:uuid/uuid.dart';

class Keys {

}

/// https://identity.foundation/peer-did-method-spec/#authorization
class AuthorizationRules {

  /// List of rules object
  List<AuthorizationRule> _rules;

  /// Constructor
  AuthorizationRules.create();

  /// Add new rule from AuthorizationRule object
  ///
  /// Usage:
  /// AuthorizationRules.create()
  ///   .add(AuthorizationRule.grant(...).when(...))
  ///   .add(AuthorizationRule.grant(...).when(...))
  ///   ...
  ///   .add(AuthorizationRule.grant(...).when(...));
  ///
  /// Or:
  /// AuthorizationRules.create().add(AuthorizationRule.fromMap(...));
  AuthorizationRules add(AuthorizationRule rule) { _rules.add(rule); return this; }

  /// Returns the map version of this class
  Map toMap() { var list = []; for (var rule in _rules) { list.add(rule.toMap()); } return { 'rules': list }; }
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

  /// List of grants to be permitted
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

  /// Returns the map version of this class
  Map toMap() => {
    'grant': _grants,
    'when': _when,
    'id': _id
  };
}

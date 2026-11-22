object d3215780eb033c7e625b94c68f9eb904a0f5ed9b
type commit
tag 4.2.7
tagger Spomky-Labs <contact@spomky-labs.com> 1794150818 +0000

### Release Notes for [4.2.7](https://github.com/web-token/jwt-framework/milestone/87)

4.2.x bugfix release (patch)

### 4.2.7

- Total issues resolved: **7**
- Total pull requests resolved: **9**
- Total contributors: **1**

#### bug

 - [789: fix(bundle): keep the key attribute of the alias lists](https://github.com/web-token/jwt-framework/pull/789) thanks to @Spomky
 - [787: fix(key-mgmt): keep the JKU/X5U requests whose headers cannot be serialized](https://github.com/web-token/jwt-framework/pull/787) thanks to @Spomky
 - [785: fix(bundle): stop merging the alias lists of a service by position](https://github.com/web-token/jwt-framework/pull/785) thanks to @Spomky
 - [782: fix(core): Base64UrlSafe rejects the bytes outside the alphabet when ext-sodium is loaded](https://github.com/web-token/jwt-framework/pull/782) thanks to @Spomky
 - [781: fix(key-mgmt): include the request headers in the key of the JKU/X5U cache](https://github.com/web-token/jwt-framework/pull/781) thanks to @Spomky
 - [779: fix: refuse header checkers that a loader factory cannot apply](https://github.com/web-token/jwt-framework/pull/779) thanks to @Spomky
 - [777: fix(checker): CallableChecker accepts a value only when its callable returns true](https://github.com/web-token/jwt-framework/pull/777) thanks to @Spomky
 - [776: fix(key-management): keep an x5u entry from naming a local file](https://github.com/web-token/jwt-framework/pull/776) thanks to @Spomky
 - [775: fix(encryption): compute ECDH-SS from the two static keys only](https://github.com/web-token/jwt-framework/pull/775) thanks to @Spomky

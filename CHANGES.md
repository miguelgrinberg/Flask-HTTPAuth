# Flask-HTTPAuth change log

**Release 4.2.0** - 2020-11-16

- Allow error response to return a 200 status code [#114](https://github.com/miguelgrinberg/Flask-HTTPAuth/issues/114) ([commit](https://github.com/miguelgrinberg/Flask-HTTPAuth/commit/f3e6a5754e89cda30fa88ef8b9dfa31e1697a688))
- Add optional argument to MultiAuth class [#115](https://github.com/miguelgrinberg/Flask-HTTPAuth/issues/115) ([commit](https://github.com/miguelgrinberg/Flask-HTTPAuth/commit/e3c6e5fb0481c14c326460408c2d0d038adf7ddc)) (thanks **pryankster** and **Michael Wright**!)
- Remove python 3.5 and add python 3.9 to build ([commit](https://github.com/miguelgrinberg/Flask-HTTPAuth/commit/507a7c0bfdf7da3bfb6a0cff9624295cf1119986))

**Release 4.1.0** - 2020-06-04

- Basic authentication with custom scheme ([commit](https://github.com/miguelgrinberg/Flask-HTTPAuth/commit/1aaf872716cb46330fd49e89663da1a568e54f0b))

**Release 4.0.0** - 2020-04-26

- Return user object from verify callbacks ([commit](https://github.com/miguelgrinberg/Flask-HTTPAuth/commit/51748c24f5aa53175b0f2712b814f7ea581f04e4))
- New role authorization support ([commit](https://github.com/miguelgrinberg/Flask-HTTPAuth/commit/8178f6dd74dab47b993ba532dd12f0cfdb5799f1)) (thanks **gemerden**!)
- Add a custom token authorization header option ([commit](https://github.com/miguelgrinberg/Flask-HTTPAuth/commit/575b46ade7188152e1b82de84be949bf3f8a300b)) (thanks **Mohamed Feddad**!)
- Support an optional=True argument in `login_required` decorator ([commit](https://github.com/miguelgrinberg/Flask-HTTPAuth/commit/8ecbb1157822360f5bdb24231fd50f25a6247620)) (thanks **Saif Almansoori**!)
- Pass HTTP status code to error callback ([commit](https://github.com/miguelgrinberg/Flask-HTTPAuth/commit/fc8bcd6772b53ef5cc14cd4c6199d63cd2c71f30))
- More secure example of basic auth in the documentation ([commit](https://github.com/miguelgrinberg/Flask-HTTPAuth/commit/0043e138cd99c7e9fa179ee30ad2283f9b8c704f))
- Fix broken links in CHANGES.md and changelog template [#85](https://github.com/miguelgrinberg/Flask-HTTPAuth/issues/85) ([commit](https://github.com/miguelgrinberg/Flask-HTTPAuth/commit/96fafd43c2d0275f2d4042e95faefce24183ec02)) (thanks **Katie Smith**!)

**Release 3.3.0** - 2019-05-19

- Use constant time string comparisons [#82](https://github.com/miguelgrinberg/Flask-HTTPAuth/issues/82) ([commit1](https://github.com/miguelgrinberg/Flask-HTTPAuth/commit/788d42ea9c4d536af628e0e7f4cb1fb84fc59a8e), [commit2](https://github.com/miguelgrinberg/Flask-HTTPAuth/commit/97f0e641a6d5eb34054de1ca255e932313d441ee)) (thanks **Brendan Long**!)
- Edited and changed the usage of JWT, because in fact the code and documentation uses JWS tokens. [#79](https://github.com/miguelgrinberg/Flask-HTTPAuth/issues/79) ([commit](https://github.com/miguelgrinberg/Flask-HTTPAuth/commit/3f743c661e281d728bd2f98af8cca000a975bb8a)) (thanks **unuseless**!)
- Documentation fix [#78](https://github.com/miguelgrinberg/Flask-HTTPAuth/issues/78) ([commit](https://github.com/miguelgrinberg/Flask-HTTPAuth/commit/c38c52326b78c91d4410f347abcd8bc49cc63ca4))
- Documentation improvements [#77](https://github.com/miguelgrinberg/Flask-HTTPAuth/issues/77) ([commit](https://github.com/miguelgrinberg/Flask-HTTPAuth/commit/ce5e5b4c9e8b748eba886ded5180e1e5d5036528))
- helper release script ([commit](https://github.com/miguelgrinberg/Flask-HTTPAuth/commit/7276d8db4b695645b01f3275addbec10418da63d))

**Release 3.2.4** - 2018-06-17

- Refactored HTTPAuth login_required [#74](https://github.com/miguelgrinberg/Flask-HTTPAuth/issues/74) ([commit](https://github.com/miguelgrinberg/Flask-HTTPAuth/commit/68ee1e7a92355ba0f3f9b48c9489a67ab762e106)) (thanks **nestedsoftware**!)
- remove incorrect references to JWT in example application [#69](https://github.com/miguelgrinberg/Flask-HTTPAuth/issues/69) ([commit](https://github.com/miguelgrinberg/Flask-HTTPAuth/commit/a310b78db2b947ab70f3fc35c1a586d822acc7ca))
- Fix typo in docs [#70](https://github.com/miguelgrinberg/Flask-HTTPAuth/issues/70) ([commit](https://github.com/miguelgrinberg/Flask-HTTPAuth/commit/b6457ae5648a50df75f3c40af4b4b3f0155fc25f)) (thanks **Grey Li**!)
- Fix documentation [#67](https://github.com/miguelgrinberg/Flask-HTTPAuth/issues/67) ([commit](https://github.com/miguelgrinberg/Flask-HTTPAuth/commit/9bd8f4b4f3574c7ef3e2fb9596bc9e9981275011)) (thanks **Eugene Rymarev**!)
- correct spelling mistake [#56](https://github.com/miguelgrinberg/Flask-HTTPAuth/issues/56) ([commit](https://github.com/miguelgrinberg/Flask-HTTPAuth/commit/f7c5bbd1b3a53080171bbdc5f1f1842f7a825f6a)) (thanks **Edward Betts**!)
- travis build fix for py36 ([commit](https://github.com/miguelgrinberg/Flask-HTTPAuth/commit/6e7f32984bda8b82200793c1b3ec44ff3df3ad2b))

**Release 3.2.3** - 2017-06-05

- Include docs and tests in pypi source tarball [#55](https://github.com/miguelgrinberg/Flask-HTTPAuth/issues/55) ([commit](https://github.com/miguelgrinberg/Flask-HTTPAuth/commit/054810ee351148b14571ba0a89ec17a543c35078)) (thanks **Chandan Kumar**!)

**Release 3.2.2** - 2017-01-30

- Validate authorization header in multi auth [#51](https://github.com/miguelgrinberg/Flask-HTTPAuth/issues/51) ([commit](https://github.com/miguelgrinberg/Flask-HTTPAuth/commit/7a895d676a1b6998f58b61a177286b62dc2872f5))
- index.rst: Add a missing variable in a code snippet [#49](https://github.com/miguelgrinberg/Flask-HTTPAuth/issues/49) ([commit](https://github.com/miguelgrinberg/Flask-HTTPAuth/commit/f7fe976bbdc699e8bafaed729dfdd74d2b27d7db)) (thanks **Baptiste Fontaine**!)

**Release 3.2.1** - 2016-09-04

- add `__version__` to package ([commit](https://github.com/miguelgrinberg/Flask-HTTPAuth/commit/d188450987f226568fe0cdee0b6d480b375af64a))
- Add readme and license files to the built package [#45](https://github.com/miguelgrinberg/Flask-HTTPAuth/issues/45) ([commit](https://github.com/miguelgrinberg/Flask-HTTPAuth/commit/1c35bec606f147bb23725d6ff3b0411f06828492))

**Release 3.2.0** - 2016-08-20

- Fix TCP Connection reset by peer error [#39](https://github.com/miguelgrinberg/Flask-HTTPAuth/issues/39) ([commit](https://github.com/miguelgrinberg/Flask-HTTPAuth/commit/94f6c6d5a4866a43ff4f269eb351dce6232791a2)) (thanks **Joe Kemp**!)

**Release 3.1.2** - 2016-04-21

- Add robustness to password check ([commit](https://github.com/miguelgrinberg/Flask-HTTPAuth/commit/051fd88ee36a21a13255b4ec69e172c9ae4ad46d))

**Release 3.1.1** - 2016-03-24

- pass params to view function in MultiAuth [#36](https://github.com/miguelgrinberg/Flask-HTTPAuth/issues/36) ([commit](https://github.com/miguelgrinberg/Flask-HTTPAuth/commit/319974602e55529006b9a8a4fde04ef08e042e83)) (thanks **vovanz**!)
- add examples to flake8 build ([commit](https://github.com/miguelgrinberg/Flask-HTTPAuth/commit/61b1b71b3b29f2936ac6a2077883da1faeaad09f))
- Added multi auth tests ([commit](https://github.com/miguelgrinberg/Flask-HTTPAuth/commit/c443e7ebcc227fd3690c2cf943d414087d7b931d))
- removed dead code ([commit](https://github.com/miguelgrinberg/Flask-HTTPAuth/commit/4d2232e2a77f5e10e1731936f4ac64439049b220))

**Release 3.1.0** - 2016-03-13

- examples ([commit](https://github.com/miguelgrinberg/Flask-HTTPAuth/commit/609806a1c10264818e08ba0ce9b7babeaf101656))
- Added support for multiple authentication methods ([commit](https://github.com/miguelgrinberg/Flask-HTTPAuth/commit/6c3f94d9eda85b78a8c36cd5e05d6d9836bee2d0))
- Added change log ([commit](https://github.com/miguelgrinberg/Flask-HTTPAuth/commit/8b427b962114a6ef13badaf8f2f1b396c540955a))
- Add additional token auth test ([commit](https://github.com/miguelgrinberg/Flask-HTTPAuth/commit/29edb1948f086babbd1a9e0c87a0a35c05f0a63b))

**Release 3.0.2** - 2016-03-12

- Let callback decide what to do when authentication type does not match ([commit](https://github.com/miguelgrinberg/Flask-HTTPAuth/commit/b942f980970d2e387a80f68de4ea2bb8728b149c))

**Release 3.0.1** - 2016-03-09

- Catching exception when Authorization header is empty ([commit](https://github.com/miguelgrinberg/Flask-HTTPAuth/commit/88d073e05b56b810feb447d1c9cee7a9a9ac9b1b)) (thanks **Kari Hreinsson**!)
- Documentation fix, validate_token() -> verify_token() ([commit](https://github.com/miguelgrinberg/Flask-HTTPAuth/commit/f4b41d736311638978c95c9b5fd458063a009280)) (thanks **Kari Hreinsson**!)

**Release 3.0.0** - 2016-03-07

- documentation for new token auth ([commit](https://github.com/miguelgrinberg/Flask-HTTPAuth/commit/c0ae42df517a45be87f419cbb7f8002228a1e83c))
- switch travis build to use tox ([commit](https://github.com/miguelgrinberg/Flask-HTTPAuth/commit/00fdebce667e1dbbc5b342a21804cb6ab3b4f417))
- token auth support, plus test reorg ([commit](https://github.com/miguelgrinberg/Flask-HTTPAuth/commit/aac866de14c68a4d17d3098f8e96102e837add1d))
- Added explicity Python 2 & 3 version classifiers to package ([commit](https://github.com/miguelgrinberg/Flask-HTTPAuth/commit/a6f50e7be6f13bb814c47fe8a3a44cd34138f87e))

**Release 2.7.1** - 2016-02-07

- Remove session dependency in authenticate_header [#31](https://github.com/miguelgrinberg/Flask-HTTPAuth/issues/31) ([commit](https://github.com/miguelgrinberg/Flask-HTTPAuth/commit/8a84c52d2166e7fdfa26b89dfd2df3340787de94)) (thanks **Paweł Stiasny**!)
- Add Install Notes ([commit](https://github.com/miguelgrinberg/Flask-HTTPAuth/commit/0ff88331c9724999d8f283d79fe95de949e64438)) (thanks **Michael Washburn Jr**!)
- Add syntax highlighting to the README [#28](https://github.com/miguelgrinberg/Flask-HTTPAuth/issues/28) ([commit](https://github.com/miguelgrinberg/Flask-HTTPAuth/commit/5c058b5165cdbc6a869d68410ef2d25e7802d602)) (thanks **Josh Friend**!)

**Release 2.7.0** - 2015-09-20

- Support custom authentication scheme and realm ([commit](https://github.com/miguelgrinberg/Flask-HTTPAuth/commit/bf12f959bba24a2f3d7d799d1b57ef3a5f1001e8))

**Release 2.6.0** - 2015-08-23

- Added information on how to implement digest authentication securely ([commit](https://github.com/miguelgrinberg/Flask-HTTPAuth/commit/fb02625ca0f7694d8e744e0b3d2c8d4ffcc4d7cd))
- Allow for custom nonce/opaque generation [#24](https://github.com/miguelgrinberg/Flask-HTTPAuth/issues/24) ([commit](https://github.com/miguelgrinberg/Flask-HTTPAuth/commit/ddaa3b6461705d107655c7f87f90d7ba962d2a84)) (thanks **Matt Haggard**!)
- fixed tests to work with python 2.6 ([commit](https://github.com/miguelgrinberg/Flask-HTTPAuth/commit/5e85b27a06285fb5bd591f9f65a8a0bebc4a34f2))
- added travis ci badge ([commit](https://github.com/miguelgrinberg/Flask-HTTPAuth/commit/ef354fd07abd08137beba6362debdcb4ef23baf6))

**release 2.5.0** - 2015-04-26

- documentation changes ([commit](https://github.com/miguelgrinberg/Flask-HTTPAuth/commit/5c98ed8370355a60e22e017a79d5575adadb9c07))
- documentation for stored ha1 feature ([commit](https://github.com/miguelgrinberg/Flask-HTTPAuth/commit/37fd9288abb4f11abf9f93303d1bce4e6cfc3c19))
- Include notes for nginx ([commit](https://github.com/miguelgrinberg/Flask-HTTPAuth/commit/ed8b4a3c954240cde0c66af3d6dae37df48ba976)) (thanks **Erik Stephens**!)
- Include notes for nginx as well ([commit](https://github.com/miguelgrinberg/Flask-HTTPAuth/commit/5bccbae862cbf1ca7d02f717b076aca86b1456e5)) (thanks **Erik Stephens**!)
- Update docs with WSGI notes ([commit](https://github.com/miguelgrinberg/Flask-HTTPAuth/commit/9ddd55f0bcb793a49675274dc22ae15122a8a1ff)) (thanks **Erik Stephens**!)
- Update README with WSGI notes ([commit](https://github.com/miguelgrinberg/Flask-HTTPAuth/commit/af5fa26dc73d401de7760ba3dcd61828c2e548dd)) (thanks **Erik Stephens**!)
- Modified documents and readme for correct import statement [#19](https://github.com/miguelgrinberg/Flask-HTTPAuth/issues/19) ([commit](https://github.com/miguelgrinberg/Flask-HTTPAuth/commit/b75737593f3d97b18620440e7e41ee9b71b23f11)) (thanks **Aayush Kasurde**!)

**release 2.4.0** - 2015-03-02

- Support anonymous users in verify_password callback ([commit](https://github.com/miguelgrinberg/Flask-HTTPAuth/commit/5c5396bbb7af540a7aff786ce3282657566045f2))
- Add HA1 generation function to HTTPDigestAuth class ([commit](https://github.com/miguelgrinberg/Flask-HTTPAuth/commit/4f4aed3ed3fa5e96a1a052e4414f14d1fc49b8bb)) (thanks **Pawel Szczurko**!)
- Fix unit test url routes ([commit](https://github.com/miguelgrinberg/Flask-HTTPAuth/commit/a490a521a17313ce82bfe886912b1620166eb6dd)) (thanks **Pawel Szczurko**!)
- Add option to use ha1 combination as password instead of plain text password ([commit](https://github.com/miguelgrinberg/Flask-HTTPAuth/commit/c84429f541ed0069f40fb901dcb3df44b801c9a5)) (thanks **Pawel Szczurko**!)
- removed extra strip() calls in unit tests ([commit](https://github.com/miguelgrinberg/Flask-HTTPAuth/commit/fc34cc5020168ca3824cc4a740b2010bb3132abf))

**release 2.3.0** - 2014-09-23

- pep8 ([commit](https://github.com/miguelgrinberg/Flask-HTTPAuth/commit/4657d5b37e50483ecccabf0887ea417d3b94ea0a))
- Fixed problem with couple of decorator that destroy function they decorate [#11](https://github.com/miguelgrinberg/Flask-HTTPAuth/issues/11) ([commit](https://github.com/miguelgrinberg/Flask-HTTPAuth/commit/0adf45bec7e5fb04a0e14e13396fd867879026b4)) (thanks **Nemanja Trifunovic**!)
- Ignore authentication headers for OPTIONS ([commit](https://github.com/miguelgrinberg/Flask-HTTPAuth/commit/044b7d4a44425a4b9d02280b80988e8986641a0d)) (thanks **Henrique Carvalho Alves**!)

**release 2.2.1** - 2014-03-17

- [#5](https://github.com/miguelgrinberg/Flask-HTTPAuth/issues/5): correct handling of None return from get_password callback ([commit](https://github.com/miguelgrinberg/Flask-HTTPAuth/commit/b94dc8e5fb6c914fdf971085b329bf9ad848a8f5))
- [#5](https://github.com/miguelgrinberg/Flask-HTTPAuth/issues/5) ([commit](https://github.com/miguelgrinberg/Flask-HTTPAuth/commit/051195d68d8aaf6d9e53d14d69a59afd84f24821))
- Fixed problem when get_password decorator destroys function it decorates [#4](https://github.com/miguelgrinberg/Flask-HTTPAuth/issues/4) ([commit](https://github.com/miguelgrinberg/Flask-HTTPAuth/commit/0cbee173e96f8e1a533e7d82b5b1fa1bfce3cd04)) (thanks **Nemanja Trifunovic**!)
- custom password verification callback ([commit](https://github.com/miguelgrinberg/Flask-HTTPAuth/commit/33d60f21a6e64f1b2df24ea5035164110979d8ab))

**version 2.1.0** - 2013-09-28

- pass the username to the hash password callback ([commit](https://github.com/miguelgrinberg/Flask-HTTPAuth/commit/13075ec4dbe4cb733f4f433e1e25e8a180fce1f6))

**Release 2.0.0** - 2013-09-26

- changed auth.username to auth.username() ([commit](https://github.com/miguelgrinberg/Flask-HTTPAuth/commit/5168a5f703552ec092e3fef9e087052e35fb6ff0))
- 2.0 documentation update ([commit](https://github.com/miguelgrinberg/Flask-HTTPAuth/commit/e668f59cb674e45891b7d9548e5af3028f2fd22d))

**Release 1.1.0** - 2013-08-30

- python 3 support ([commit](https://github.com/miguelgrinberg/Flask-HTTPAuth/commit/c13ff0a4c1e5922a635ea7c877a2ef6079ddb4e6))
- documentation update ([commit](https://github.com/miguelgrinberg/Flask-HTTPAuth/commit/c468e1c084e5c25dcaa85b45e5abeb88fbc09420))

**Release 1.0.0** - 2013-07-27

- First official release!

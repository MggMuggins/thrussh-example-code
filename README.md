# thrussh example code
In order to get this code building/running on redox:

```sh
# Someting like this, wherever you cloned redox
cd redox/cookbook/recipes/thrussh-test
git clone https://github.com/MggMuggins/thrussh-example-code source

echo BUILD_DEPENDS=(openssl libsodium) > recipe.sh
```
Then go through the whole cookbook routine to deploy to a redox vm.

**Disclaimer**: This does not actually run on redox, it just builds.

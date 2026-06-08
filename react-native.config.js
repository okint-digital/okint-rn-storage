// Autolinking descriptor for consuming apps.
module.exports = {
  dependency: {
    platforms: {
      android: {
        sourceDir: 'android',
        packageImportPath: 'import com.okint.rnstorage.OkintRnStoragePackage;',
        packageInstance: 'new OkintRnStoragePackage()',
      },
      ios: {
        podspecPath: __dirname + '/okint-rn-storage.podspec',
      },
    },
  },
};

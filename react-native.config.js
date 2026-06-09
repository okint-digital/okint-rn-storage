// Autolinking descriptor for consuming apps.
module.exports = {
  dependency: {
    platforms: {
      android: {
        sourceDir: 'android',
        packageImportPath: 'import com.okint.rnstorage.OkintRnStoragePackage;',
        packageInstance: 'new OkintRnStoragePackage()',
      },
      // iOS: no entry needed. The CLI auto-discovers our single root podspec
      // (okint-rn-storage.podspec). An explicit `podspecPath` here is rejected
      // by the RN CLI dependency-config schema (it's a project-config key, not
      // a dependency-config one) and emits an "invalid configuration" warning.
    },
  },
};

// This module has no admin UI: OTP settings are managed through the standard Store settings screen.
var moduleName = 'VirtoCommerce.Otp';

if (AppDependencies !== undefined) {
    AppDependencies.push(moduleName);
}

angular.module(moduleName, []);

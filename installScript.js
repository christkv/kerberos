'use strict';
const os = require('os');
const execSync = require('child_process').execSync;
const platformDevDependencies = require('./package.json').platformDevDependencies;

// Install platform specific devDependencies using custom key "platformDevDependencies"
// in package.json
if (process.env.NODE_ENV !== 'production') {
  try {
    require('prettier');
    Object.keys(platformDevDependencies).forEach(d => {
      const version = platformDevDependencies[d].version;
      const targets = platformDevDependencies[d].targets;
      if (targets.indexOf(os.type()) > -1) {
        execSync(`npm install --no-save ${d}@${version}`, { stdio: ['ignore', 'ignore', 'inherit'] });
      }
    });
  } catch (e) {}
}
execSync("prebuild-install || node-gyp rebuild", { stdio: 'inherit' });

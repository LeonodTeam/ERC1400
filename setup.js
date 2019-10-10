// 'use strict';
fs = require('fs');
fs.createReadStream('auth.template.json')
  .pipe(fs.createWriteStream('auth.json'));

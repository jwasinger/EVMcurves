const path = require('path');
const fs = require('fs');

const { compiler } = require('./huff/src');
const parser = require('./huff/src/parser');

const pathToData = path.posix.resolve(__dirname, './');

let file_name = process.argv[3];
if (!file_name) {
    file_name = 'main.huff'
}

const { inputMap, macros, jumptables } = parser.parseFile(file_name, pathToData);

var arg = process.argv[2];


const {
    data: { bytecode: macroCode },
} = parser.processMacro(arg, 0, [], macros, inputMap, jumptables);
console.log(macroCode)

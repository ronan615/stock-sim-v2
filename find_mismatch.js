const fs = require('fs');
const content = fs.readFileSync('client_script.js', 'utf8');
let balance = 0;
let lines = content.split('\n');
lines.forEach((line, i) => {
    let prev = balance;
    for (let char of line) {
        if (char === "{") balance++;
        if (char === "}") balance--;
    }
    if (balance !== prev) {
        console.log("Line " + (i + 1) + " | Balance " + prev + " -> " + balance + " | " + line.trim());
    }
});
console.log("Final balance:", balance);

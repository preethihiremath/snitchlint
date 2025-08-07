declare const req: any;
declare const document: any;

const name = req.query.name;
document.write(name);

function render(userInput: string) {
  document.body.innerHTML = "<div>" + userInput + "</div>";  // Should trigger
}

const userInput = req.query.x;
let element = document.createElement("div");
element.innerHTML = userInput; // This should trigger your XSS analyzer

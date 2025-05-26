
// Mock Express-like request object for testing
const req = {
    body: {
        username: "user_input_name",
        id: "user_input_id",
        details: { nestedValue: "user_nested_value"}
    },
    query: {
        productId: "user_query_productId"
    },
    params: {
        orderId: "user_param_orderId"
    }
};

// Mock database connection
const db = {
    query: function(sql, params) {
        console.log("DB: Executing SQL Query:", sql, "with params:", params);
    },
    execute: function(sql) {
        console.log("DB: Executing SQL Execute:", sql);
    },
    raw: function(sql) {
        console.log("DB: Executing SQL Raw:", sql);
    }
};
const someOtherDb = db;


// --- Test Cases ---

function directTaintVariable() {
    console.log("--- Running directTaintVariable ---");
    const userId = req.body.id; // SOURCE: 'userId' becomes tainted
    const query1 = `SELECT * FROM users WHERE id = '${userId}'`; // SINK: 'userId' used
    db.query(query1); // Diagnostic expected for query1

    const productName = req.query.productId; // SOURCE: 'productName' becomes tainted
    db.execute("SELECT * FROM products WHERE name = '" + productName + "'"); // SINK: 'productName' used (argument 0)
}
directTaintVariable();

function directTaintPropertyAccess() {
    console.log("--- Running directTaintPropertyAccess ---");
    const item = req.body; // SOURCE: 'item' becomes tainted (as it's assigned req.body)
    const queryNested = `SELECT * FROM items WHERE data = '${item.details.nestedValue}'`; // SINK: item.details.nestedValue (base 'item' is tainted)
    db.query(queryNested); // Diagnostic expected for item.details.nestedValue
}
directTaintPropertyAccess();


function destructuredTaint() {
    console.log("--- Running destructuredTaint ---");
    const { username } = req.body; // SOURCE: 'username' becomes tainted
    const query2 = `SELECT * FROM accounts WHERE owner = '${username}'`; // SINK: 'username' used
    someOtherDb.query(query2); // Diagnostic expected for query2
}
destructuredTaint();

function assignmentTaint() {
    console.log("--- Running assignmentTaint ---");
    let orderDetails;
    orderDetails = req.params.orderId; // SOURCE: 'orderDetails' becomes tainted by assignment
    const query3 = `SELECT * FROM orders WHERE order_id = ${orderDetails}`; // SINK: 'orderDetails' used
    db.raw(query3); // Diagnostic expected for query3
}
assignmentTaint();

function environmentVariableTaint() {
    console.log("--- Running environmentVariableTaint ---");
    // For this to work, 'process.env' must be in TAINT_SOURCES.
    // The analyzer matches if the initializer *starts with* 'process.env'.
    // A more precise check would identify specific sensitive env vars.
    const apiKey = process.env.USER_API_KEY; // SOURCE: 'apiKey' becomes tainted
    if (apiKey) {
        db.query(`UPDATE settings SET key_value = '${apiKey}' WHERE key_name = 'api'`); // SINK
    }
}
// Note: To make process.env.USER_API_KEY work with `startsWith`, TAINT_SOURCES
// should include "process.env" (which it does in the provided taintUtils.ts).
environmentVariableTaint();


function safeUsage() {
    console.log("--- Running safeUsage ---");
    const safeId = "123_admin_fixed";
    const anotherSafeVal = 100;
    const querySafe = `SELECT * FROM logs WHERE admin_id = '${safeId}' AND value = ${anotherSafeVal}`;
    db.query(querySafe); // No diagnostic expected

    const safeInput = "user_input"; // Not from a TAINT_SOURCE
    db.execute(`SELECT * FROM data WHERE val = '${safeInput}'`); // No diagnostic expected
}
safeUsage();


// --- Test cases highlighting limitations (might not be caught or caught broadly) ---
function complexPropagationNotCaught() {
    console.log("--- Running complexPropagationNotCaught ---");
    let id = req.body.id; // 'id' is tainted
    function getId() {
        return id; // This function now effectively returns tainted data
    }
    const propagatedId = getId(); // 'propagatedId' is tainted, but analyzer might not know this
                               // without inter-procedural analysis.
    db.query(`SELECT * FROM things WHERE thing_id = '${propagatedId}'`); // MAY NOT BE CAUGHT

    const obj = {};
    obj.key = req.query.productId; // obj.key is tainted. 'obj' itself isn't directly from a source.
    db.query(`SELECT * FROM complex WHERE key = '${obj.key}'`); // MAY NOT BE CAUGHT unless 'obj' is tainted
                                                              // or it can trace obj.key to req.query.productId
}
// The current `isExpressionTainted` for PropertyAccess checks if the base object ('obj') is tainted.
// Since 'obj' is initialized as '{}', it's not tainted directly from a source.
// Tainting `obj.key = ...` would require a more advanced analysis of assignments to properties.
complexPropagationNotCaught();

console.log("Test file loaded and executed.");
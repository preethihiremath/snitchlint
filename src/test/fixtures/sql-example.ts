declare const db: any;
declare const req: any;

function testSQL() {
  const id = req.query.id;
  const query = `SELECT * FROM users WHERE id = ${id}`;
  db.query(query);
}

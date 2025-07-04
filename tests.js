const jwt = require('jsonwebtoken');

function testTokenTampering() {
  const token = jwt.sign({ id: 1, role: 'admin' }, 'secret_key');
  const tampered = token.replace('admin', 'user');
  try {
    jwt.verify(tampered, 'secret_key');
    console.log("❌ Tampering undetected");
  } catch {
    console.log("✅ Token tampering detected");
  }
}

function testXSSProtection() {
  const malicious = `<script>alert('XSS')</script>`;
  const isSafe = !malicious.includes('<script>');
  console.log(isSafe ? "✅ XSS input rejected" : "❌ XSS input accepted");
}

testTokenTampering();
testXSSProtection();

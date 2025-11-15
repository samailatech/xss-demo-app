const express = require('express');
const bodyParser = require('body-parser');
const sanitizeHtml = require('sanitize-html');
const helmet = require('helmet');

const app = express();
const PORT = process.env.PORT || 3003;

// simple in-memory comments storage
const comments = [];

app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());

// Helmet adds various security headers, including CSP control
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"], // disallow inline scripts by default
      objectSrc: ["'none'"]
    }
  }
}));

// 1) Vulnerable route - stores raw HTML (DON'T use in real apps)
app.get('/vulnerable', (req, res) => {
  res.send(`
    <h2>Vulnerable Comments (Stored XSS)</h2>
    <form method="POST" action="/vulnerable">
      <input name="name" placeholder="name" /><br/>
      <textarea name="comment" placeholder="comment"></textarea><br/>
      <button>Post</button>
    </form>
    <hr/>
    ${comments.map(c => `<div><strong>${c.name}</strong>: ${c.comment}</div>`).join('')}
    <hr/><a href="/">Back</a>
  `);
});

app.post('/vulnerable', (req, res) => {
  // Intentionally store raw user input
  comments.push({ name: req.body.name || 'anon', comment: req.body.comment || '' });
  res.redirect('/vulnerable');
});

// 2) Fixed route - sanitizes input and escapes output
app.get('/safe', (req, res) => {
  res.send(`
    <h2>Safe Comments (Sanitized + Escaped)</h2>
    <form method="POST" action="/safe">
      <input name="name" placeholder="name" /><br/>
      <textarea name="comment" placeholder="comment"></textarea><br/>
      <button>Post</button>
    </form>
    <hr/>
    ${comments.map(c => {
      // show sanitized comment (demonstrates fix even if comments array contains malicious HTML)
      const safeName = sanitizeHtml(c.name, { allowedTags: [], allowedAttributes: {} });
      const safeComment = sanitizeHtml(c.comment, {
        allowedTags: ['b','i','em','strong','a'],
        allowedAttributes: { a: ['href', 'rel', 'target'] },
        transformTags: {
          'a': (tagName, attribs) => {
            // force safe link attrs
            attribs.rel = 'noopener noreferrer';
            attribs.target = '_blank';
            return { tagName, attribs };
          }
        }
      });
      return `<div><strong>${safeName}</strong>: ${safeComment}</div>`;
    }).join('')}
    <hr/><a href="/">Back</a>
  `);
});

app.post('/safe', (req, res) => {
  // sanitize BEFORE storing (optional) -- demonstrate both
  const name = sanitizeHtml(req.body.name || 'anon', { allowedTags: [], allowedAttributes: {} });
  const comment = req.body.comment || '';
  // store raw for demo to show why sanitization/escaping on output is required
  comments.push({ name, comment });
  res.redirect('/safe');
});

app.get('/', (req, res) => {
  res.send(`
    <h1>XSS Demo</h1>
    <ul>
      <li><a href="/vulnerable">Vulnerable Comments</a> (shows XSS)</li>
      <li><a href="/safe">Safe Comments</a> (sanitized + CSP)</li>
    </ul>
  `);
});

app.listen(PORT, () => console.log(`XSS demo running at http://localhost:${PORT}`));

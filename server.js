
const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const dns = require("node:dns").promises;
const https = require("node:https");
const rateLimit = require("express-rate-limit");

const app = express();
const PORT = process.env.PORT || 3000;

app.use(helmet());
app.use(cors());
app.use(express.json({ limit: "10kb" }));

app.use("/api", rateLimit({
  windowMs: 60 * 1000,
  limit: 10
}));

app.get("/", (req, res) => {
  res.json({
    service: "Humphreyrich Cyber Defence",
    version: "5.0",
    status: "online"
  });
});

app.get("/health", (req, res) => {
  res.json({ status: "healthy" });
});

function checkHttps(domain) {
  return new Promise((resolve) => {
    const request = https.request({
      hostname: domain,
      method: "HEAD",
      path: "/",
      timeout: 8000
    }, (response) => {
      resolve({
        secure: true,
        statusCode: response.statusCode,
        headers: {
          strictTransportSecurity:
            response.headers["strict-transport-security"] || null,
          contentSecurityPolicy:
            response.headers["content-security-policy"] || null,
          xContentTypeOptions:
            response.headers["x-content-type-options"] || null,
          referrerPolicy:
            response.headers["referrer-policy"] || null
        }
      });
      response.resume();
    });

    request.on("timeout", () => {
      request.destroy(new Error("Request timed out"));
    });

    request.on("error", () => {
      resolve({ secure: false, error: "HTTPS check failed" });
    });

    request.end();
  });
}

app.post("/api/scan", async (req, res) => {
  const domain = String(req.body.domain || "")
    .trim()
    .toLowerCase();

  if (
    domain.length > 253 ||
    !/^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/.test(domain)
  ) {
    return res.status(400).json({
      error: "Enter a valid domain name."
    });
  }

  try {
    const [addresses, mx, ns, txt] = await Promise.all([
      dns.resolve4(domain).catch(() => []),
      dns.resolveMx(domain).catch(() => []),
      dns.resolveNs(domain).catch(() => []),
      dns.resolveTxt(domain).catch(() => [])
    ]);

    const httpsResult = await checkHttps(domain);

    const findings = [];

    if (!addresses.length) {
      findings.push("No IPv4 DNS record was found.");
    }

    if (!httpsResult.secure) {
      findings.push("HTTPS connection could not be verified.");
    } else {
      if (!httpsResult.headers.strictTransportSecurity) {
        findings.push("HSTS security header was not detected.");
      }
      if (!httpsResult.headers.contentSecurityPolicy) {
        findings.push("Content Security Policy was not detected.");
      }
      if (!httpsResult.headers.xContentTypeOptions) {
        findings.push("X-Content-Type-Options was not detected.");
      }
    }

    res.json({
      domain,
      scannedAt: new Date().toISOString(),
      addresses,
      mx,
      ns,
      txt,
      https: httpsResult,
      findings,
      note: "This is a basic DNS and HTTPS configuration check, not a penetration test."
    });

  } catch (error) {
    res.status(500).json({
      error: "The check could not be completed."
    });
  }
});

app.listen(PORT, () => {
  console.log(`Humphreyrich Cyber Defence running on port ${PORT}`);
});

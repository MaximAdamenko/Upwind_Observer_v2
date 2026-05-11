const API_URL = "https://api.yourdomain.com";
const API_KEY = "upwind-obs-2026-xK9mQ3vR7tY2wZ5p";

// Entry point — triggered when a Gmail message is opened
function onGmailMessage(e) {
  const messageId = e.gmail.messageId;
  const accessToken = e.gmail.accessToken;
  GmailApp.setCurrentMessageAccessToken(accessToken);

  const message = GmailApp.getMessageById(messageId);
  if (!message) return _errorCard("Could not retrieve message.");

  // Collect attachments as base64-encoded content so the backend can hash real bytes
  const attachments = message.getAttachments().map(att => ({
    filename: att.getName(),
    content_b64: Utilities.base64Encode(att.getBytes()),
  }));

  const payload = JSON.stringify({
    raw_content: message.getRawContent(),
    body: message.getPlainBody(),
    attachments: attachments,
  });

  try {
    const resp = UrlFetchApp.fetch(`${API_URL}/v1/scan`, {
      method: "post",
      contentType: "application/json",
      headers: { Authorization: `Bearer ${API_KEY}` },
      payload: payload,
      muteHttpExceptions: true,
    });

    const data = JSON.parse(resp.getContentText());
    if (!data.job_id) return _errorCard("Scan submission failed:\n" + resp.getContentText());

    PropertiesService.getUserProperties().setProperty("currentJobId", data.job_id);
    return _pendingCard(data.job_id);
  } catch (err) {
    return _errorCard("Network error: " + err.message);
  }
}

// Called when user clicks "View Threat Report"
// Polls until the job is complete (up to ~30 s)
function showReasoning() {
  const jobId = PropertiesService.getUserProperties().getProperty("currentJobId");
  if (!jobId) {
    return CardService.newActionResponseBuilder()
      .setNotification(CardService.newNotification().setText("No active scan found. Open an email first."))
      .build();
  }

  let report = null;
  let finalStatus = "pending";

  for (let attempt = 0; attempt < 10; attempt++) {
    const resp = UrlFetchApp.fetch(`${API_URL}/v1/results/${jobId}`, {
      method: "get",
      headers: { Authorization: `Bearer ${API_KEY}` },
      muteHttpExceptions: true,
    });
    const data = JSON.parse(resp.getContentText());
    finalStatus = data.status;

    if (finalStatus === "completed") { report = data.report; break; }
    if (finalStatus === "failed")    { break; }

    Utilities.sleep(3000); // wait 3 s before next poll
  }

  if (finalStatus === "failed") {
    return CardService.newActionResponseBuilder()
      .setNotification(CardService.newNotification().setText("Analysis failed. Check server logs."))
      .build();
  }
  if (!report) {
    return CardService.newActionResponseBuilder()
      .setNotification(CardService.newNotification().setText("Analysis is still running. Try again in a moment."))
      .build();
  }

  return CardService.newActionResponseBuilder()
    .setNavigation(CardService.newNavigation().pushCard(_reportCard(report)))
    .build();
}

// ─── Card builders ───────────────────────────────────────────────────────────

function _pendingCard(jobId) {
  return CardService.newCardBuilder()
    .setHeader(CardService.newCardHeader().setTitle("Upwind Observer").setSubtitle("Analyzing…"))
    .addSection(
      CardService.newCardSection()
        .addWidget(CardService.newTextParagraph().setText("Your email is being analyzed. Click below when ready."))
        .addWidget(
          CardService.newTextButton()
            .setText("View Threat Report")
            .setOnClickAction(CardService.newAction().setFunctionName("showReasoning"))
        )
    )
    .build();
}

function _errorCard(message) {
  return CardService.newCardBuilder()
    .setHeader(CardService.newCardHeader().setTitle("Upwind Observer").setSubtitle("Error"))
    .addSection(
      CardService.newCardSection()
        .addWidget(CardService.newTextParagraph().setText(message))
    )
    .build();
}

function _reportCard(report) {
  const score = report.score || 0;
  const risk = (report.risk_level || "low").toUpperCase();
  const riskEmoji = score < 30 ? "🟢" : score < 70 ? "🟡" : "🔴";

  const classLabel = {
    "Commercial": "📧 Commercial — looks like a regular marketing or newsletter email.",
    "Credential Stealing": "🎣 Credential Stealing — this email is trying to steal your login or personal info.",
    "Malware": "☠️ Malware — this email may be delivering malicious software or links.",
  }[report.ai_classification] || "❓ Unknown — could not determine email type.";

  const authLine =
    `DMARC: ${report.dmarc_status}  |  SPF: ${report.spf_status}  |  DKIM: ${report.dkim_status}`;

  const iocs = report.iocs || {};
  const allIocs = [...(iocs.ips || []), ...(iocs.urls || [])].slice(0, 8);
  const vtHits = (report.virustotal_hits || []).filter(h => h.malicious);

  // ── Overview section ──────────────────────────────────────────────────────
  const overview = CardService.newCardSection()
    .setHeader("Overview")
    .addWidget(CardService.newKeyValue()
      .setTopLabel("Threat Score")
      .setContent(`${riskEmoji} ${score} / 100 — ${risk}`))
    .addWidget(CardService.newKeyValue()
      .setTopLabel("Email Type")
      .setContent(classLabel))
    .addWidget(CardService.newKeyValue()
      .setTopLabel("Email Authentication")
      .setContent(authLine));

  // ── What we found section ─────────────────────────────────────────────────
  const findings = CardService.newCardSection()
    .setHeader("What We Found")
    .addWidget(CardService.newTextParagraph()
      .setText(report.ai_reasoning || "No additional details available."));

  if (allIocs.length) {
    findings.addWidget(CardService.newKeyValue()
      .setTopLabel(`Suspicious Links / IPs (${allIocs.length})`)
      .setContent(allIocs.join("\n")));
  }

  if (vtHits.length) {
    findings.addWidget(CardService.newKeyValue()
      .setTopLabel(`⚠️ VirusTotal Flagged (${vtHits.length})`)
      .setContent(vtHits.map(h => `${h.item} — ${h.detections} engines`).join("\n")));
  }

  if ((report.attachment_hashes || []).length) {
    findings.addWidget(CardService.newKeyValue()
      .setTopLabel("Attachment SHA-256")
      .setContent(report.attachment_hashes.join("\n")));
  }

  return CardService.newCardBuilder()
    .setHeader(CardService.newCardHeader()
      .setTitle("Upwind Observer")
      .setSubtitle("Threat Report"))
    .addSection(overview)
    .addSection(findings)
    .build();
}

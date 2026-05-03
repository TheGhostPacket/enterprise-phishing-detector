# ============================================================
# ADD THESE IMPORTS at the top of app.py with other imports
# ============================================================

# from attachment_analyzer import get_attachment_analyzer
# from webhook_alerts import get_webhook_alerter

# ADD THESE after scan_history and threat_feed initialization:
# attachment_analyzer_instance = get_attachment_analyzer()
# webhook_alerter = get_webhook_alerter()


# ============================================================
# ADD THESE ROUTES to app.py
# ============================================================

# ── ATTACHMENT ANALYSIS ──────────────────────────────────────

@app.route('/analyze-attachment', methods=['POST'])
@limiter.limit("20 per hour")
def analyze_attachment():
    """Analyze an email attachment for phishing indicators."""
    try:
        d = request.get_json(silent=True)
        if not d:
            return jsonify({'success': False, 'error': 'Invalid JSON body'}), 400

        filename = str(d.get('filename', '') or '').strip()[:255]
        file_data = str(d.get('file_data', '') or '').strip()

        if not filename:
            return jsonify({'success': False, 'error': 'Provide a filename'}), 400
        if not file_data:
            return jsonify({'success': False, 'error': 'Provide file data'}), 400

        result = attachment_analyzer_instance.analyze_base64(filename, file_data)

        # Save to history
        if result.get('success'):
            scan_history.add_scan('attachment', filename, {
                'danger_score': result.get('risk_score', 0),
                'risk_level': result.get('risk_level', 'unknown'),
                'reasons': result.get('risk_factors', []),
                'summary': result.get('summary', '')
            })

        return jsonify(result)
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


# ── WEBHOOK ALERTS ───────────────────────────────────────────

@app.route('/webhook/test', methods=['POST'])
@limiter.limit("10 per hour")
def test_webhook():
    """Test a webhook URL by sending a test message."""
    try:
        d = request.get_json(silent=True)
        if not d:
            return jsonify({'success': False, 'error': 'Invalid JSON body'}), 400

        webhook_url = str(d.get('webhook_url', '') or '').strip()
        if not webhook_url:
            return jsonify({'success': False, 'error': 'Provide a webhook URL'}), 400
        if not webhook_url.startswith('https://'):
            return jsonify({'success': False, 'error': 'Webhook URL must start with https://'}), 400

        result = webhook_alerter.test_webhook(webhook_url)
        return jsonify(result)
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/webhook/alert', methods=['POST'])
@limiter.limit("30 per hour")
def send_webhook_alert():
    """Send a threat alert to a webhook URL."""
    try:
        d = request.get_json(silent=True)
        if not d:
            return jsonify({'success': False, 'error': 'Invalid JSON body'}), 400

        webhook_url = str(d.get('webhook_url', '') or '').strip()
        scan_type   = str(d.get('scan_type', 'unknown') or 'unknown').strip()
        target      = str(d.get('target', '') or '').strip()[:200]
        risk_level  = str(d.get('risk_level', '') or '').strip()
        risk_score  = int(d.get('risk_score', 0) or 0)
        risk_factors = d.get('risk_factors', [])

        if not webhook_url:
            return jsonify({'success': False, 'error': 'Provide a webhook URL'}), 400
        if not webhook_url.startswith('https://'):
            return jsonify({'success': False, 'error': 'Webhook URL must start with https://'}), 400

        result = webhook_alerter.send_slack_alert(
            webhook_url, scan_type, target,
            risk_level, risk_score, risk_factors
        )
        return jsonify(result)
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

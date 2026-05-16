"""API routes for the Honeypot-as-a-Service platform.

Extended with AI threat intelligence, GeoIP, campaign, and analytics endpoints.
"""

from flask import Blueprint, jsonify, request
from flask_login import login_required
from datetime import datetime, timedelta
from sqlalchemy import func

from app import db
from app.models import AttackLog, HoneypotService, Campaign, ThreatIntelFeed, AlertHistory

api_bp = Blueprint('api', __name__)


@api_bp.route('/attacks', methods=['GET'])
@login_required
def get_attacks():
    """Get attack logs with optional filtering."""
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 50, type=int)
    honeypot_type = request.args.get('type')
    severity = request.args.get('severity')
    hours = request.args.get('hours', type=int)
    classification = request.args.get('classification')
    min_score = request.args.get('min_score', type=float)

    query = AttackLog.query

    if honeypot_type:
        query = query.filter_by(honeypot_type=honeypot_type)
    if severity:
        query = query.filter_by(severity=severity)
    if classification:
        query = query.filter_by(ai_classification=classification)
    if min_score:
        query = query.filter(AttackLog.threat_score >= min_score)
    if hours:
        since = datetime.utcnow() - timedelta(hours=hours)
        query = query.filter(AttackLog.timestamp >= since)

    query = query.order_by(AttackLog.timestamp.desc())
    pagination = query.paginate(page=page, per_page=per_page, error_out=False)

    return jsonify({
        'attacks': [a.to_dict() for a in pagination.items],
        'total': pagination.total,
        'pages': pagination.pages,
        'current_page': page
    })


@api_bp.route('/attacks/recent', methods=['GET'])
@login_required
def get_recent_attacks():
    """Get the most recent attacks."""
    limit = request.args.get('limit', 20, type=int)
    attacks = AttackLog.query.order_by(
        AttackLog.timestamp.desc()
    ).limit(limit).all()

    return jsonify({'attacks': [a.to_dict() for a in attacks]})


@api_bp.route('/stats', methods=['GET'])
@login_required
def get_stats():
    """Get dashboard statistics."""
    now = datetime.utcnow()
    last_24h = now - timedelta(hours=24)

    total_attacks = AttackLog.query.count()
    attacks_24h = AttackLog.query.filter(AttackLog.timestamp >= last_24h).count()
    unique_ips = db.session.query(func.count(func.distinct(AttackLog.source_ip))).scalar()

    attacks_by_type = db.session.query(
        AttackLog.honeypot_type, func.count(AttackLog.id)
    ).group_by(AttackLog.honeypot_type).all()

    attacks_by_severity = db.session.query(
        AttackLog.severity, func.count(AttackLog.id)
    ).group_by(AttackLog.severity).all()

    top_ips = db.session.query(
        AttackLog.source_ip, func.count(AttackLog.id).label('count')
    ).group_by(AttackLog.source_ip).order_by(
        func.count(AttackLog.id).desc()
    ).limit(10).all()

    # Hourly attack trend
    hourly_trend = []
    for i in range(24):
        hour_start = now - timedelta(hours=i+1)
        hour_end = now - timedelta(hours=i)
        count = AttackLog.query.filter(
            AttackLog.timestamp >= hour_start,
            AttackLog.timestamp < hour_end
        ).count()
        hourly_trend.append({'hour': hour_start.strftime('%H:%M'), 'count': count})

    # AI-specific stats
    ai_classifications = db.session.query(
        AttackLog.ai_classification, func.count(AttackLog.id)
    ).filter(AttackLog.ai_classification.isnot(None)).group_by(
        AttackLog.ai_classification
    ).all()

    avg_threat_score = db.session.query(
        func.avg(AttackLog.threat_score)
    ).filter(AttackLog.threat_score.isnot(None)).scalar() or 0

    anomaly_count = AttackLog.query.filter_by(is_anomaly=True).count()
    campaign_count = db.session.query(func.count(func.distinct(AttackLog.campaign_id))).filter(
        AttackLog.campaign_id.isnot(None)
    ).scalar()

    # Country distribution
    country_stats = db.session.query(
        AttackLog.geoip_country_code, func.count(AttackLog.id)
    ).filter(AttackLog.geoip_country_code.isnot(None)).group_by(
        AttackLog.geoip_country_code
    ).order_by(func.count(AttackLog.id).desc()).limit(15).all()

    return jsonify({
        'total_attacks': total_attacks,
        'attacks_24h': attacks_24h,
        'unique_ips': unique_ips,
        'attacks_by_type': dict(attacks_by_type),
        'attacks_by_severity': dict(attacks_by_severity),
        'top_ips': [{'ip': ip, 'count': count} for ip, count in top_ips],
        'hourly_trend': list(reversed(hourly_trend)),
        # AI stats
        'ai_classifications': dict(ai_classifications),
        'avg_threat_score': round(avg_threat_score, 2),
        'anomaly_count': anomaly_count,
        'campaign_count': campaign_count,
        'country_stats': [{'code': code, 'count': count} for code, count in country_stats]
    })


@api_bp.route('/services', methods=['GET'])
@login_required
def get_services():
    """Get honeypot service status."""
    services = HoneypotService.query.all()
    return jsonify({'services': [s.to_dict() for s in services]})


@api_bp.route('/services/<service_type>/toggle', methods=['POST'])
@login_required
def toggle_service(service_type):
    """Toggle a honeypot service on/off."""
    from app.honeypots.manager import HoneypotManager

    manager = HoneypotManager.get_instance()
    if not manager:
        return jsonify({'error': 'Honeypot manager not initialized'}), 500

    service = HoneypotService.query.filter_by(service_type=service_type).first()
    if not service:
        return jsonify({'error': 'Service not found'}), 404

    if service.status == 'running':
        manager.stop_honeypot(service_type)
        return jsonify({'message': f'{service_type} honeypot stopped', 'status': 'stopped'})
    else:
        manager.start_honeypot(service_type)
        return jsonify({'message': f'{service_type} honeypot started', 'status': 'running'})


# ============================================================
# AI & THREAT INTELLIGENCE ENDPOINTS
# ============================================================

@api_bp.route('/ai/threats', methods=['GET'])
@login_required
def get_ai_threats():
    """Get current AI threat intelligence."""
    from app.ai.analyzer import AttackAnalyzer

    analyzer = AttackAnalyzer.get_instance()
    if not analyzer:
        return jsonify({'error': 'AI not initialized'}), 500

    intel = analyzer.get_threat_intelligence()
    return jsonify(intel)


@api_bp.route('/ai/ip/<ip_address>', methods=['GET'])
@login_required
def get_ip_analysis(ip_address):
    """Get AI analysis for a specific IP."""
    # Get attack history for this IP
    attacks = AttackLog.query.filter_by(source_ip=ip_address)\
        .order_by(AttackLog.timestamp.desc()).limit(50).all()

    # Get threat intel
    intel = ThreatIntelFeed.query.filter_by(ip_address=ip_address).first()

    # Get AI analysis
    from app.ai.analyzer import AttackAnalyzer
    analyzer = AttackAnalyzer.get_instance()
    ai_data = analyzer.get_ip_analysis(ip_address) if analyzer else {}

    return jsonify({
        'ip': ip_address,
        'total_attacks': len(attacks),
        'attacks': [a.to_dict() for a in attacks[:20]],
        'threat_intel': intel.to_dict() if intel else None,
        'ai_analysis': ai_data,
        'first_seen': attacks[-1].timestamp.isoformat() if attacks else None,
        'last_seen': attacks[0].timestamp.isoformat() if attacks else None
    })


@api_bp.route('/campaigns', methods=['GET'])
@login_required
def get_campaigns():
    """Get detected attack campaigns."""
    campaigns = db.session.query(
        AttackLog.campaign_id,
        func.count(AttackLog.id).label('attack_count'),
        func.count(func.distinct(AttackLog.source_ip)).label('ip_count'),
        func.min(AttackLog.timestamp).label('first_seen'),
        func.max(AttackLog.timestamp).label('last_seen')
    ).filter(AttackLog.campaign_id.isnot(None)).group_by(
        AttackLog.campaign_id
    ).order_by(func.count(AttackLog.id).desc()).limit(20).all()

    return jsonify({
        'campaigns': [{
            'campaign_id': c.campaign_id,
            'attack_count': c.attack_count,
            'ip_count': c.ip_count,
            'first_seen': c.first_seen.isoformat() if c.first_seen else None,
            'last_seen': c.last_seen.isoformat() if c.last_seen else None
        } for c in campaigns]
    })


@api_bp.route('/geo/heatmap', methods=['GET'])
@login_required
def get_geo_heatmap():
    """Get geographic attack data for heatmap visualization."""
    attacks_with_geo = AttackLog.query.filter(
        AttackLog.geoip_latitude.isnot(None),
        AttackLog.geoip_longitude.isnot(None)
    ).order_by(AttackLog.timestamp.desc()).limit(500).all()

    points = []
    for a in attacks_with_geo:
        points.append({
            'lat': a.geoip_latitude,
            'lng': a.geoip_longitude,
            'ip': a.source_ip,
            'country': a.geoip_country,
            'severity': a.severity,
            'score': a.threat_score or 0
        })

    return jsonify({'points': points})


@api_bp.route('/alerts/history', methods=['GET'])
@login_required
def get_alert_history():
    """Get recent alert history."""
    limit = request.args.get('limit', 50, type=int)
    alerts = AlertHistory.query.order_by(
        AlertHistory.triggered_at.desc()
    ).limit(limit).all()

    return jsonify({'alerts': [a.to_dict() for a in alerts]})

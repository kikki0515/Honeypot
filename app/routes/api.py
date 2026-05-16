"""API routes for the Honeypot-as-a-Service platform."""

from flask import Blueprint, jsonify, request
from flask_login import login_required
from datetime import datetime, timedelta
from sqlalchemy import func

from app import db
from app.models import AttackLog, HoneypotService

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

    query = AttackLog.query

    if honeypot_type:
        query = query.filter_by(honeypot_type=honeypot_type)
    if severity:
        query = query.filter_by(severity=severity)
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
    last_7d = now - timedelta(days=7)

    # Total attacks
    total_attacks = AttackLog.query.count()

    # Attacks in last 24 hours
    attacks_24h = AttackLog.query.filter(
        AttackLog.timestamp >= last_24h
    ).count()

    # Unique IPs
    unique_ips = db.session.query(
        func.count(func.distinct(AttackLog.source_ip))
    ).scalar()

    # Attacks by type
    attacks_by_type = db.session.query(
        AttackLog.honeypot_type,
        func.count(AttackLog.id)
    ).group_by(AttackLog.honeypot_type).all()

    # Attacks by severity
    attacks_by_severity = db.session.query(
        AttackLog.severity,
        func.count(AttackLog.id)
    ).group_by(AttackLog.severity).all()

    # Top attacking IPs
    top_ips = db.session.query(
        AttackLog.source_ip,
        func.count(AttackLog.id).label('count')
    ).group_by(AttackLog.source_ip).order_by(
        func.count(AttackLog.id).desc()
    ).limit(10).all()

    # Hourly attack trend (last 24 hours)
    hourly_trend = []
    for i in range(24):
        hour_start = now - timedelta(hours=i+1)
        hour_end = now - timedelta(hours=i)
        count = AttackLog.query.filter(
            AttackLog.timestamp >= hour_start,
            AttackLog.timestamp < hour_end
        ).count()
        hourly_trend.append({
            'hour': hour_start.strftime('%H:%M'),
            'count': count
        })

    return jsonify({
        'total_attacks': total_attacks,
        'attacks_24h': attacks_24h,
        'unique_ips': unique_ips,
        'attacks_by_type': dict(attacks_by_type),
        'attacks_by_severity': dict(attacks_by_severity),
        'top_ips': [{'ip': ip, 'count': count} for ip, count in top_ips],
        'hourly_trend': list(reversed(hourly_trend))
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

from .models import AuditLog, AuditAction

def record_audit(actor, action: str, target_object: str, ip_address: str = "127.0.0.1", metadata: dict = None):
    """
    Helper function to safely record audit events.
    """
    actor_str = "SYSTEM"
    if actor and hasattr(actor, 'username'):
        actor_str = actor.username
    elif isinstance(actor, str) and actor:
        actor_str = actor

    metadata = metadata or {}
    try:
        return AuditLog.objects.create(
            actor=actor_str,
            action=action,
            target_object=str(target_object)[:255],
            ip_address=str(ip_address)[:45],
            metadata=metadata
        )
    except Exception:
        return None

#!/usr/bin/env python3
"""
TrapNinja Control Socket Command Handlers

Handler implementations for control socket commands. Each handler
processes a specific command type (HA operations, stats queries,
config display, etc.) and returns a response dictionary.

This module provides the ControlHandlers mixin that is inherited by
the ControlSocket class in control.py, keeping socket infrastructure
separate from command logic.

Supported command groups:
    HA operations:   ha_status, ha_promote, ha_demote, ha_force_failover
    Service:         service_status
    Configuration:   show_config, config_sync
    Statistics:      stats (with action sub-routing)
"""

import logging
from typing import Dict, Any

logger = logging.getLogger("trapninja")


class ControlHandlers:
    """
    Mixin providing command handler implementations for ControlSocket.

    Expects the inheriting class to define response status codes:
        SUCCESS, ERROR, NOT_FOUND, INVALID_REQUEST
    """

    # -----------------------------------------------------------------
    # HA handlers
    # -----------------------------------------------------------------

    def _handle_ha_status(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """Handle HA status request."""
        try:
            from .ha import get_ha_cluster

            ha_cluster = get_ha_cluster()
            if not ha_cluster:
                return {
                    'status': self.NOT_FOUND,
                    'error': 'HA cluster not initialized'
                }

            ha_status = ha_cluster.get_status()
            return {
                'status': self.SUCCESS,
                'data': ha_status
            }
        except Exception as e:
            return {
                'status': self.ERROR,
                'error': f'Error getting HA status: {e}'
            }

    def _handle_ha_promote(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """Handle HA promote request."""
        try:
            from .ha import get_ha_cluster

            ha_cluster = get_ha_cluster()
            if not ha_cluster:
                return {
                    'status': self.NOT_FOUND,
                    'error': 'HA cluster not running'
                }

            force = request.get('force', False)
            success = ha_cluster.promote_to_primary(force=force)

            if success:
                return {
                    'status': self.SUCCESS,
                    'message': f'Promotion initiated (force={force})'
                }
            else:
                return {
                    'status': self.ERROR,
                    'error': 'Promotion failed'
                }
        except Exception as e:
            return {
                'status': self.ERROR,
                'error': f'Error promoting to PRIMARY: {e}'
            }

    def _handle_ha_demote(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """Handle HA demote request."""
        try:
            from .ha import get_ha_cluster

            ha_cluster = get_ha_cluster()
            if not ha_cluster:
                return {
                    'status': self.NOT_FOUND,
                    'error': 'HA cluster not running'
                }

            success = ha_cluster.demote_to_secondary()

            if success:
                return {
                    'status': self.SUCCESS,
                    'message': 'Demotion successful'
                }
            else:
                return {
                    'status': self.ERROR,
                    'error': 'Demotion failed'
                }
        except Exception as e:
            return {
                'status': self.ERROR,
                'error': f'Error demoting to SECONDARY: {e}'
            }

    def _handle_ha_force_failover(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """Handle HA force failover request."""
        try:
            from .ha import get_ha_cluster

            ha_cluster = get_ha_cluster()
            if not ha_cluster:
                return {
                    'status': self.NOT_FOUND,
                    'error': 'HA cluster not running'
                }

            ha_cluster.force_failover()

            return {
                'status': self.SUCCESS,
                'message': 'Force failover initiated'
            }
        except Exception as e:
            return {
                'status': self.ERROR,
                'error': f'Error forcing failover: {e}'
            }

    # -----------------------------------------------------------------
    # Service handlers
    # -----------------------------------------------------------------

    def _handle_service_status(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """Handle service status request."""
        try:
            from .metrics import get_metrics_summary
            from .ha import get_ha_cluster

            metrics = get_metrics_summary()

            ha_cluster = get_ha_cluster()
            ha_status = ha_cluster.get_status() if ha_cluster else None

            return {
                'status': self.SUCCESS,
                'data': {
                    'metrics': metrics,
                    'ha': ha_status
                }
            }
        except Exception as e:
            return {
                'status': self.ERROR,
                'error': f'Error getting service status: {e}'
            }

    # -----------------------------------------------------------------
    # Configuration handlers
    # -----------------------------------------------------------------

    def _handle_config_sync(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """Handle configuration synchronisation request."""
        try:
            from .ha import get_ha_cluster

            ha_cluster = get_ha_cluster()
            if not ha_cluster:
                return {
                    'status': self.NOT_FOUND,
                    'error': 'HA cluster not running'
                }

            if not hasattr(ha_cluster, 'sync_config') or not ha_cluster.config_sync:
                return {
                    'status': self.NOT_FOUND,
                    'error': 'Config sync not available'
                }

            force = request.get('force', False)
            result = ha_cluster.sync_config(force=force)

            return {
                'status': self.SUCCESS,
                'data': result
            }
        except Exception as e:
            logger.error(f"Error handling config sync: {e}")
            return {
                'status': self.ERROR,
                'error': f'Error during config sync: {e}'
            }

    def _handle_show_config(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """Handle show configuration request."""
        try:
            from . import config as cfg
            from .ha import load_ha_config

            config = {
                'config_directory': cfg.CONFIG_DIR,
                'interface': cfg.INTERFACE,
                'capture_mode': cfg.CAPTURE_MODE,
                'listen_ports': list(cfg.LISTEN_PORTS),
                'forwarding': {
                    'destinations': cfg.destinations,
                    'destination_count': (
                        len(cfg.destinations) if cfg.destinations else 0
                    ),
                },
                'filtering': {
                    'blocked_ips_count': (
                        len(cfg.blocked_ips) if cfg.blocked_ips else 0
                    ),
                    'blocked_oids_count': (
                        len(cfg.blocked_traps) if cfg.blocked_traps else 0
                    ),
                    'ip_redirections_count': (
                        len(cfg.redirected_ips) if cfg.redirected_ips else 0
                    ),
                    'oid_redirections_count': (
                        len(cfg.redirected_oids) if cfg.redirected_oids else 0
                    ),
                    'redirect_destinations_count': (
                        len(cfg.redirected_destinations)
                        if cfg.redirected_destinations else 0
                    ),
                },
            }

            # Add HA configuration
            try:
                ha_config = load_ha_config()
                config['high_availability'] = {
                    'enabled': ha_config.enabled,
                    'mode': ha_config.mode,
                    'priority': ha_config.priority,
                    'peer_host': (
                        ha_config.peer_host if ha_config.enabled else None
                    ),
                    'peer_port': (
                        ha_config.peer_port if ha_config.enabled else None
                    ),
                    'heartbeat_interval': ha_config.heartbeat_interval,
                    'failover_delay': ha_config.failover_delay,
                }
            except Exception:
                config['high_availability'] = {'enabled': False}

            # Add cache configuration
            try:
                from .config import load_cache_config
                cache_config = load_cache_config()
                if cache_config:
                    config['cache'] = {
                        'enabled': cache_config.enabled,
                        'host': (
                            cache_config.host if cache_config.enabled else None
                        ),
                        'port': (
                            cache_config.port if cache_config.enabled else None
                        ),
                        'retention_hours': cache_config.retention_hours,
                    }
            except Exception:
                config['cache'] = {'enabled': False}

            return {
                'status': self.SUCCESS,
                'data': config
            }

        except Exception as e:
            logger.error(f"Error getting configuration: {e}")
            return {
                'status': self.ERROR,
                'error': f'Error getting configuration: {e}'
            }

    # -----------------------------------------------------------------
    # Statistics handlers
    # -----------------------------------------------------------------

    def _handle_stats(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """Handle granular statistics requests."""
        try:
            from .stats import get_stats_collector

            collector = get_stats_collector()
            if not collector:
                return {
                    'status': self.NOT_FOUND,
                    'error': 'Statistics collector not initialized'
                }

            action = request.get('action', 'summary')

            # Route to specific stats handler
            handler = self._STATS_ACTIONS.get(action)
            if handler:
                return handler(self, request, collector)
            else:
                return {
                    'status': self.INVALID_REQUEST,
                    'error': f'Unknown stats action: {action}'
                }

        except Exception as e:
            logger.error(f"Error handling stats request: {e}")
            return {
                'status': self.ERROR,
                'error': f'Error getting statistics: {e}'
            }

    def _stats_summary(self, request, collector):
        """Get statistics summary."""
        return {
            'status': self.SUCCESS,
            'data': collector.get_summary()
        }

    def _stats_top_ips(self, request, collector):
        """Get top source IPs."""
        count = min(request.get('count', 10), 100)
        sort_by = request.get('sort_by', 'total')
        return {
            'status': self.SUCCESS,
            'data': collector.get_top_ips(n=count, sort_by=sort_by)
        }

    def _stats_top_oids(self, request, collector):
        """Get top OIDs."""
        count = min(request.get('count', 10), 100)
        sort_by = request.get('sort_by', 'total')
        return {
            'status': self.SUCCESS,
            'data': collector.get_top_oids(n=count, sort_by=sort_by)
        }

    def _stats_ip_detail(self, request, collector):
        """Get IP address detail."""
        ip_address = request.get('ip_address')
        if not ip_address:
            return {
                'status': self.INVALID_REQUEST,
                'error': 'ip_address required'
            }
        top_n_oids = min(request.get('top_n_oids', 10), 500)
        data = collector.get_ip_stats(ip_address, top_n_oids=top_n_oids)
        if data:
            return {'status': self.SUCCESS, 'data': data}
        return {
            'status': self.NOT_FOUND,
            'error': f'IP {ip_address} not found'
        }

    def _stats_oid_detail(self, request, collector):
        """Get OID detail."""
        oid = request.get('oid')
        if not oid:
            return {
                'status': self.INVALID_REQUEST,
                'error': 'oid required'
            }
        top_n_sources = min(request.get('top_n_sources', 10), 500)
        data = collector.get_oid_stats(oid, top_n_sources=top_n_sources)
        if data:
            return {'status': self.SUCCESS, 'data': data}
        return {
            'status': self.NOT_FOUND,
            'error': f'OID {oid} not found'
        }

    def _stats_destinations(self, request, collector):
        """Get destination statistics."""
        return {
            'status': self.SUCCESS,
            'data': collector.get_all_destinations()
        }

    def _stats_dashboard(self, request, collector):
        """Get dashboard snapshot."""
        snapshot = collector.get_snapshot(top_n=50)
        return {
            'status': self.SUCCESS,
            'data': snapshot.to_dict()
        }

    def _stats_reset(self, request, collector):
        """Reset all statistics."""
        collector.reset()
        return {
            'status': self.SUCCESS,
            'message': 'Statistics reset'
        }

    def _stats_debug(self, request, collector):
        """Get debug diagnostic information."""
        from .processing.stats import get_global_stats
        from .network import get_queue_stats
        from .ha import is_forwarding_enabled, get_ha_cluster
        from .shadow import (
            is_shadow_mode, is_observe_only, get_effective_capture_mode
        )

        processing_stats = get_global_stats()
        queue_stats = get_queue_stats()

        ha_cluster = get_ha_cluster()
        ha_info = {
            'enabled': (
                ha_cluster is not None and ha_cluster.config.enabled
                if ha_cluster else False
            ),
            'is_forwarding': is_forwarding_enabled(),
            'state': (
                ha_cluster.current_state.value
                if ha_cluster else 'disabled'
            ),
        }

        capture_info = {
            'shadow_mode': is_shadow_mode(),
            'observe_only': is_observe_only(),
            'effective_mode': get_effective_capture_mode(),
        }

        debug_info = {
            'granular_collector': {
                'initialized': collector is not None,
                'running': collector._running if collector else False,
                'total_traps': collector._total_traps if collector else 0,
                'unique_ips': (
                    len(collector._ip_stats) if collector else 0
                ),
                'unique_oids': (
                    len(collector._oid_stats) if collector else 0
                ),
            },
            'processing_stats': (
                processing_stats.to_dict() if processing_stats else {}
            ),
            'queue_stats': queue_stats,
            'ha_status': ha_info,
            'capture_mode': capture_info,
        }
        return {
            'status': self.SUCCESS,
            'data': debug_info
        }

    # Stats action dispatch table
    _STATS_ACTIONS = {
        'summary': _stats_summary,
        'top_ips': _stats_top_ips,
        'top_oids': _stats_top_oids,
        'ip_detail': _stats_ip_detail,
        'oid_detail': _stats_oid_detail,
        'destinations': _stats_destinations,
        'dashboard': _stats_dashboard,
        'reset': _stats_reset,
        'debug': _stats_debug,
    }

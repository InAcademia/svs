import time
import logging
logger = logging.getLogger('tranaction_flow')

def transaction_log(id, order, component, type, location, status, description):
    log_entry = dict([('id', id),
                      ('component', component),
                      ('type', type),
                      ('location', location),
                      ('status', status),
                      ('description', description or ''),
                      ('timestamp', time.time()),
                ])
    logger.info('::%s::%s::%s' % (id, order, log_entry))
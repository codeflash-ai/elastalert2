# A dict containing EQL would resemble the following:
# {'query': {'bool': {'filter': {'bool': {'must': [{'range': {'@timestamp': {'gt': 'yyyy...', 'lte': 'yyyy...'}}}, {'eql': 'process where process.name == "regsvr32.exe"'}]}}}}, 'sort': [{'@timestamp': {'order': 'asc'}}]}
def format_request(body):
    query = body.get('query')
    if not query:
        return None

    query_bool = query.get('bool')
    if not query_bool:
        return None

    filter = query_bool.get('filter')
    if not filter:
        return None

    filter_bool = filter.get('bool')
    if not filter_bool:
        return None

    filter_bool_must = filter_bool.get('must')
    if not filter_bool_must:
        return None

    eql = None
    other_filters = []
    # Use local variable lookups to minimize attribute access in the loop
    append_other = other_filters.append
    for f in filter_bool_must:
        f_eql = f.get('eql')
        if f_eql:
            eql = f_eql
        else:
            append_other(f)

    if eql:
        # Pre-allocate new_body as a literal
        return {'filter': {'bool': {'must': other_filters}}, 'query': eql}

    return None

def format_results(results):
    hits = results.get('hits')
    if not hits:
        return results
    
    events = hits.get('events')
    if events is None:
        return results
    
    # relabel events as hits, for consistency
    events = hits.pop('events')
    hits['hits'] = events
    results['eql'] = True

    return results
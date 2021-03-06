/**
 * Copyright (c) Codice Foundation
 * <p>
 * This is free software: you can redistribute it and/or modify it under the terms of the GNU Lesser
 * General Public License as published by the Free Software Foundation, either version 3 of the
 * License, or any later version.
 * <p>
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without
 * even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details. A copy of the GNU Lesser General Public License
 * is distributed along with this program and can be found at
 * <http://www.gnu.org/licenses/lgpl.html>.
 */
package org.codice.ddf.catalog.ui.query.cql;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

import org.codice.ddf.catalog.ui.query.delegate.SearchTerm;
import org.codice.ddf.catalog.ui.query.delegate.SearchTermsDelegate;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import ddf.action.ActionRegistry;
import ddf.catalog.data.AttributeDescriptor;
import ddf.catalog.data.Metacard;
import ddf.catalog.data.MetacardType;
import ddf.catalog.data.Result;
import ddf.catalog.filter.FilterAdapter;
import ddf.catalog.operation.Query;
import ddf.catalog.operation.QueryRequest;
import ddf.catalog.operation.QueryResponse;
import ddf.catalog.source.UnsupportedQueryException;

public class CqlQueryResponse {

    private static final Logger LOGGER = LoggerFactory.getLogger(CqlQueryResponse.class);

    private static final SearchTermsDelegate SEARCH_TERMS_DELEGATE = new SearchTermsDelegate();

    private final List<CqlResult> results;

    private final String id;

    private final Map<String, Map<String, MetacardAttribute>> types;

    private final Status status;

    public CqlQueryResponse(String id, QueryRequest request, QueryResponse queryResponse,
            String source, long elapsedTime, boolean normalize, FilterAdapter filterAdapter,
            ActionRegistry actionRegistry) {
        this.id = id;

        status = new Status(queryResponse, source, elapsedTime);

        types = queryResponse.getResults()
                .stream()
                .map(Result::getMetacard)
                .filter(Objects::nonNull)
                .map(Metacard::getMetacardType)
                .filter(Objects::nonNull)
                .collect(Collectors.toSet())
                .stream()
                .collect(Collectors.toMap(MetacardType::getName,
                        mt -> mt.getAttributeDescriptors()
                                .stream()
                                .collect(Collectors.toMap(AttributeDescriptor::getName,
                                        MetacardAttribute::new,
                                        (ad1, ad2) -> {
                                            LOGGER.debug("Removed duplicate attribute descriptor.");
                                            return ad1;
                                        })),
                        (mt1, mt2) -> {
                            LOGGER.debug("Removed duplicate metacard type.");
                            return mt1;
                        }));

        final Set<SearchTerm> searchTerms = extractSearchTerms(request.getQuery(), filterAdapter);
        results = queryResponse.getResults()
                .stream()
                .map(result -> new CqlResult(result,
                        searchTerms,
                        queryResponse.getRequest(),
                        normalize,
                        filterAdapter,
                        actionRegistry))
                .collect(Collectors.toList());
    }

    private Set<SearchTerm> extractSearchTerms(Query query, FilterAdapter filterAdapter) {
        Set<SearchTerm> searchTerms = Collections.emptySet();
        try {
            searchTerms = filterAdapter.adapt(query, SEARCH_TERMS_DELEGATE);
        } catch (UnsupportedQueryException e) {
            LOGGER.debug("Unable to parse search terms", e);
        }
        return searchTerms;
    }

    public List<CqlResult> getResults() {
        return results;
    }

    public Map<String, Map<String, MetacardAttribute>> getTypes() {
        return types;
    }

    public String getId() {
        return id;
    }

    public Status getStatus() {
        return status;
    }
}

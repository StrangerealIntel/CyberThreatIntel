import React, { useState } from 'react'
import { useMutation } from '@tanstack/react-query'
import { search } from '../api'

function Search() {
  const [query, setQuery] = useState('')
  const [results, setResults] = useState(null)

  const searchMutation = useMutation({
    mutationFn: async (searchQuery) => {
      const response = await search({ query: searchQuery, limit: 50 })
      return response.data
    },
    onSuccess: (data) => {
      setResults(data)
    }
  })

  const handleSearch = (e) => {
    e.preventDefault()
    if (query.trim()) {
      searchMutation.mutate(query)
    }
  }

  return (
    <div className="search">
      <h1 style={{ color: '#00d9ff', marginBottom: '30px' }}>Search Threat Intelligence</h1>

      <form onSubmit={handleSearch}>
        <div style={{ display: 'flex', gap: '10px' }}>
          <input
            type="text"
            className="search-box"
            placeholder="Search across analyses and IOCs..."
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            style={{ flex: 1, marginBottom: 0 }}
          />
          <button
            type="submit"
            className="btn btn-primary"
            disabled={searchMutation.isPending}
          >
            {searchMutation.isPending ? 'Searching...' : 'Search'}
          </button>
        </div>
      </form>

      {searchMutation.isError && (
        <div className="error" style={{ marginTop: '20px' }}>
          Error: {searchMutation.error.message}
        </div>
      )}

      {results && (
        <div style={{ marginTop: '30px' }}>
          {/* Analyses Results */}
          <div className="card">
            <h2>Analyses ({results.analyses.length})</h2>
            {results.analyses.length > 0 ? (
              <table className="table">
                <thead>
                  <tr>
                    <th>Date</th>
                    <th>Title</th>
                    <th>APT Group</th>
                    <th>Country</th>
                    <th>Type</th>
                  </tr>
                </thead>
                <tbody>
                  {results.analyses.map((analysis) => (
                    <tr key={analysis._id}>
                      <td>{new Date(analysis.date).toLocaleDateString()}</td>
                      <td>
                        <strong style={{ color: '#00d9ff' }}>{analysis.title}</strong>
                      </td>
                      <td>{analysis.apt_group}</td>
                      <td>{analysis.country || 'N/A'}</td>
                      <td>
                        <span className={`badge ${
                          analysis.threat_type === 'APT' ? 'badge-danger' :
                          analysis.threat_type === 'Cybercriminal' ? 'badge-warning' :
                          'badge-info'
                        }`}>
                          {analysis.threat_type}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            ) : (
              <div style={{ padding: '20px', color: '#a0aec0', textAlign: 'center' }}>
                No analyses found
              </div>
            )}
          </div>

          {/* IOCs Results */}
          <div className="card" style={{ marginTop: '20px' }}>
            <h2>IOCs ({results.iocs.length})</h2>
            {results.iocs.length > 0 ? (
              <table className="table">
                <thead>
                  <tr>
                    <th>Type</th>
                    <th>Value</th>
                    <th>APT Group</th>
                    <th>Description</th>
                  </tr>
                </thead>
                <tbody>
                  {results.iocs.map((ioc) => (
                    <tr key={ioc._id}>
                      <td>
                        <span className={`badge ${
                          ioc.type === 'hash' ? 'badge-danger' :
                          ioc.type === 'ip' ? 'badge-warning' :
                          ioc.type === 'domain' ? 'badge-info' :
                          'badge-success'
                        }`}>
                          {ioc.type.toUpperCase()}
                        </span>
                      </td>
                      <td>
                        <code style={{
                          background: '#2d3748',
                          padding: '4px 8px',
                          borderRadius: '4px',
                          fontSize: '12px',
                          color: '#00d9ff',
                          wordBreak: 'break-all'
                        }}>
                          {ioc.value}
                        </code>
                      </td>
                      <td>{ioc.apt_group}</td>
                      <td>{ioc.description || 'N/A'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            ) : (
              <div style={{ padding: '20px', color: '#a0aec0', textAlign: 'center' }}>
                No IOCs found
              </div>
            )}
          </div>
        </div>
      )}

      {!results && !searchMutation.isPending && (
        <div style={{ marginTop: '40px', textAlign: 'center', color: '#a0aec0' }}>
          <p>Enter a search query to find analyses and IOCs</p>
          <p style={{ marginTop: '10px', fontSize: '14px' }}>
            You can search for APT groups, malware families, IOC values, or any keywords
          </p>
        </div>
      )}
    </div>
  )
}

export default Search

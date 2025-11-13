import React, { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { getIOCs } from '../api'

function IOCs() {
  const [page, setPage] = useState(0)
  const [filters, setFilters] = useState({
    ioc_type: '',
    apt_group: '',
    search: ''
  })

  const limit = 50

  const { data, isLoading, error } = useQuery({
    queryKey: ['iocs', page, filters],
    queryFn: async () => {
      const response = await getIOCs({
        offset: page * limit,
        limit,
        ...Object.fromEntries(Object.entries(filters).filter(([_, v]) => v !== ''))
      })
      return response.data
    }
  })

  if (isLoading) {
    return <div className="loading">Loading IOCs...</div>
  }

  if (error) {
    return <div className="error">Error loading IOCs: {error.message}</div>
  }

  const totalPages = Math.ceil(data.total / limit)

  return (
    <div className="iocs">
      <h1 style={{ color: '#00d9ff', marginBottom: '30px' }}>Indicators of Compromise (IOCs)</h1>

      {/* Search */}
      <input
        type="text"
        className="search-box"
        placeholder="Search IOCs by value..."
        value={filters.search}
        onChange={(e) => setFilters({ ...filters, search: e.target.value })}
      />

      {/* Filters */}
      <div className="filter-group">
        <select
          value={filters.ioc_type}
          onChange={(e) => setFilters({ ...filters, ioc_type: e.target.value })}
        >
          <option value="">All IOC Types</option>
          <option value="hash">Hash</option>
          <option value="ip">IP Address</option>
          <option value="domain">Domain</option>
          <option value="url">URL</option>
          <option value="email">Email</option>
          <option value="filename">Filename</option>
        </select>

        <button
          className="btn btn-primary"
          onClick={() => setFilters({ ioc_type: '', apt_group: '', search: '' })}
        >
          Clear Filters
        </button>
      </div>

      {/* Results Info */}
      <div style={{ marginBottom: '20px', color: '#a0aec0' }}>
        Showing {data.data.length} of {data.total} IOCs
      </div>

      {/* IOCs List */}
      <div className="card">
        <table className="table">
          <thead>
            <tr>
              <th>Type</th>
              <th>Value</th>
              <th>APT Group</th>
              <th>Description</th>
              <th>Source</th>
            </tr>
          </thead>
          <tbody>
            {data.data.map((ioc) => (
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
                <td style={{ fontSize: '11px', color: '#a0aec0' }}>
                  {ioc.source_file?.split('/').pop() || 'N/A'}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Pagination */}
      <div className="pagination">
        <button
          onClick={() => setPage(0)}
          disabled={page === 0}
        >
          First
        </button>
        <button
          onClick={() => setPage(page - 1)}
          disabled={page === 0}
        >
          Previous
        </button>
        <span style={{ padding: '8px 16px', color: '#a0aec0' }}>
          Page {page + 1} of {totalPages}
        </span>
        <button
          onClick={() => setPage(page + 1)}
          disabled={page >= totalPages - 1}
        >
          Next
        </button>
        <button
          onClick={() => setPage(totalPages - 1)}
          disabled={page >= totalPages - 1}
        >
          Last
        </button>
      </div>
    </div>
  )
}

export default IOCs

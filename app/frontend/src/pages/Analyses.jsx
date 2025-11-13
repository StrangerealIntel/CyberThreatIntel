import React, { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { getAnalyses } from '../api'

function Analyses() {
  const [page, setPage] = useState(0)
  const [filters, setFilters] = useState({
    country: '',
    apt_group: '',
    threat_type: ''
  })

  const limit = 20

  const { data, isLoading, error } = useQuery({
    queryKey: ['analyses', page, filters],
    queryFn: async () => {
      const response = await getAnalyses({
        offset: page * limit,
        limit,
        ...Object.fromEntries(Object.entries(filters).filter(([_, v]) => v !== ''))
      })
      return response.data
    }
  })

  if (isLoading) {
    return <div className="loading">Loading analyses...</div>
  }

  if (error) {
    return <div className="error">Error loading analyses: {error.message}</div>
  }

  const totalPages = Math.ceil(data.total / limit)

  return (
    <div className="analyses">
      <h1 style={{ color: '#00d9ff', marginBottom: '30px' }}>Threat Analyses</h1>

      {/* Filters */}
      <div className="filter-group">
        <select
          value={filters.country}
          onChange={(e) => setFilters({ ...filters, country: e.target.value })}
        >
          <option value="">All Countries</option>
          <option value="China">China</option>
          <option value="Russia">Russia</option>
          <option value="North Korea">North Korea</option>
          <option value="Iran">Iran</option>
          <option value="Pakistan">Pakistan</option>
          <option value="India">India</option>
        </select>

        <select
          value={filters.threat_type}
          onChange={(e) => setFilters({ ...filters, threat_type: e.target.value })}
        >
          <option value="">All Threat Types</option>
          <option value="APT">APT</option>
          <option value="Cybercriminal">Cybercriminal</option>
          <option value="Unknown">Unknown</option>
        </select>

        <button
          className="btn btn-primary"
          onClick={() => setFilters({ country: '', apt_group: '', threat_type: '' })}
        >
          Clear Filters
        </button>
      </div>

      {/* Results Info */}
      <div style={{ marginBottom: '20px', color: '#a0aec0' }}>
        Showing {data.data.length} of {data.total} analyses
      </div>

      {/* Analyses List */}
      <div className="card">
        <table className="table">
          <thead>
            <tr>
              <th>Date</th>
              <th>Title</th>
              <th>APT Group</th>
              <th>Country</th>
              <th>Type</th>
              <th>Tags</th>
            </tr>
          </thead>
          <tbody>
            {data.data.map((analysis) => (
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
                <td>
                  {analysis.tags?.slice(0, 3).map((tag, idx) => (
                    <span key={idx} className="badge badge-info">{tag}</span>
                  ))}
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

export default Analyses

import React from 'react'
import { useQuery } from '@tanstack/react-query'
import { getAPTGroups } from '../api'

function APTGroups() {
  const { data, isLoading, error } = useQuery({
    queryKey: ['apt-groups'],
    queryFn: async () => {
      const response = await getAPTGroups()
      return response.data
    }
  })

  if (isLoading) {
    return <div className="loading">Loading APT groups...</div>
  }

  if (error) {
    return <div className="error">Error loading APT groups: {error.message}</div>
  }

  return (
    <div className="apt-groups">
      <h1 style={{ color: '#00d9ff', marginBottom: '30px' }}>APT Groups</h1>

      <div style={{ marginBottom: '20px', color: '#a0aec0' }}>
        Total Groups: {data.total}
      </div>

      <div className="grid">
        {data.data.map((group) => (
          <div key={group._id} className="card">
            <h2>{group._id}</h2>
            <div style={{ marginTop: '15px', display: 'flex', flexDirection: 'column', gap: '10px' }}>
              <div>
                <strong style={{ color: '#a0aec0' }}>Country:</strong>{' '}
                <span className="badge badge-info">{group.country || 'Unknown'}</span>
              </div>
              <div>
                <strong style={{ color: '#a0aec0' }}>Type:</strong>{' '}
                <span className={`badge ${
                  group.threat_type === 'APT' ? 'badge-danger' :
                  group.threat_type === 'Cybercriminal' ? 'badge-warning' :
                  'badge-info'
                }`}>
                  {group.threat_type}
                </span>
              </div>
              <div>
                <strong style={{ color: '#a0aec0' }}>Total Analyses:</strong>{' '}
                <span style={{ color: '#00d9ff', fontWeight: 'bold' }}>
                  {group.total_analyses}
                </span>
              </div>
              {group.latest_activity && (
                <div>
                  <strong style={{ color: '#a0aec0' }}>Latest Activity:</strong>{' '}
                  {new Date(group.latest_activity).toLocaleDateString()}
                </div>
              )}
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}

export default APTGroups

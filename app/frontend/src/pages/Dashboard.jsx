import React from 'react'
import { useQuery } from '@tanstack/react-query'
import { getStatistics, getHealth } from '../api'
import { BarChart, Bar, PieChart, Pie, Cell, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer } from 'recharts'

const COLORS = ['#667eea', '#764ba2', '#f093fb', '#4facfe', '#00f2fe', '#43e97b']

function Dashboard() {
  const { data: stats, isLoading: statsLoading } = useQuery({
    queryKey: ['statistics'],
    queryFn: async () => {
      const response = await getStatistics()
      return response.data
    }
  })

  const { data: health } = useQuery({
    queryKey: ['health'],
    queryFn: async () => {
      const response = await getHealth()
      return response.data
    },
    refetchInterval: 30000 // Refresh every 30 seconds
  })

  if (statsLoading) {
    return <div className="loading">Loading dashboard...</div>
  }

  const countryData = stats?.analyses_by_country?.map(item => ({
    name: item._id || 'Unknown',
    value: item.count
  })) || []

  const typeData = stats?.analyses_by_type?.map(item => ({
    name: item._id || 'Unknown',
    value: item.count
  })) || []

  const iocTypeData = stats?.iocs_by_type?.map(item => ({
    name: item._id || 'Unknown',
    value: item.count
  })) || []

  return (
    <div className="dashboard">
      <h1 style={{ color: '#00d9ff', marginBottom: '30px' }}>Threat Intelligence Dashboard</h1>

      {/* System Health */}
      {health && (
        <div className="card" style={{ marginBottom: '30px' }}>
          <h2>System Health</h2>
          <div style={{ display: 'flex', gap: '20px', marginTop: '15px' }}>
            <div>
              <span className={`badge ${health.status === 'healthy' ? 'badge-success' : 'badge-danger'}`}>
                {health.status.toUpperCase()}
              </span>
            </div>
            <div>
              Database: <span className={health.database_connected ? 'badge badge-success' : 'badge badge-danger'}>
                {health.database_connected ? 'CONNECTED' : 'DISCONNECTED'}
              </span>
            </div>
            <div>Version: {health.version}</div>
          </div>
        </div>
      )}

      {/* Statistics Cards */}
      <div className="grid">
        <div className="stat-card" style={{ background: 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)' }}>
          <h3>Total Analyses</h3>
          <div className="value">{stats?.total_analyses || 0}</div>
        </div>
        <div className="stat-card" style={{ background: 'linear-gradient(135deg, #f093fb 0%, #f5576c 100%)' }}>
          <h3>Total IOCs</h3>
          <div className="value">{stats?.total_iocs || 0}</div>
        </div>
        <div className="stat-card" style={{ background: 'linear-gradient(135deg, #4facfe 0%, #00f2fe 100%)' }}>
          <h3>Countries</h3>
          <div className="value">{countryData.length}</div>
        </div>
        <div className="stat-card" style={{ background: 'linear-gradient(135deg, #43e97b 0%, #38f9d7 100%)' }}>
          <h3>Threat Types</h3>
          <div className="value">{typeData.length}</div>
        </div>
      </div>

      {/* Charts */}
      <div className="grid" style={{ gridTemplateColumns: '1fr 1fr' }}>
        <div className="card">
          <h2>Analyses by Country</h2>
          <ResponsiveContainer width="100%" height={300}>
            <BarChart data={countryData}>
              <CartesianGrid strokeDasharray="3 3" stroke="#2d3748" />
              <XAxis dataKey="name" stroke="#a0aec0" />
              <YAxis stroke="#a0aec0" />
              <Tooltip
                contentStyle={{ background: '#1a1f2e', border: '1px solid #2d3748', borderRadius: '8px' }}
                labelStyle={{ color: '#00d9ff' }}
              />
              <Bar dataKey="value" fill="#667eea" />
            </BarChart>
          </ResponsiveContainer>
        </div>

        <div className="card">
          <h2>Analyses by Type</h2>
          <ResponsiveContainer width="100%" height={300}>
            <PieChart>
              <Pie
                data={typeData}
                cx="50%"
                cy="50%"
                labelLine={false}
                label={({ name, percent }) => `${name}: ${(percent * 100).toFixed(0)}%`}
                outerRadius={100}
                fill="#8884d8"
                dataKey="value"
              >
                {typeData.map((entry, index) => (
                  <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                ))}
              </Pie>
              <Tooltip
                contentStyle={{ background: '#1a1f2e', border: '1px solid #2d3748', borderRadius: '8px' }}
              />
            </PieChart>
          </ResponsiveContainer>
        </div>

        <div className="card" style={{ gridColumn: 'span 2' }}>
          <h2>IOCs by Type</h2>
          <ResponsiveContainer width="100%" height={300}>
            <BarChart data={iocTypeData} layout="vertical">
              <CartesianGrid strokeDasharray="3 3" stroke="#2d3748" />
              <XAxis type="number" stroke="#a0aec0" />
              <YAxis dataKey="name" type="category" stroke="#a0aec0" />
              <Tooltip
                contentStyle={{ background: '#1a1f2e', border: '1px solid #2d3748', borderRadius: '8px' }}
                labelStyle={{ color: '#00d9ff' }}
              />
              <Bar dataKey="value" fill="#f5576c" />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>
    </div>
  )
}

export default Dashboard

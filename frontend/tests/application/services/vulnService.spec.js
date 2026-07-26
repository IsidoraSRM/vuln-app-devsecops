import { describe, it, expect, vi } from 'vitest'
import vulnService from '@/application/services/vulnService'
import apiClient from '@/infrastructure/http/apiClient'

// Mock the apiClient module
vi.mock('@/infrastructure/http/apiClient', () => {
    return {
        default: {
            get: vi.fn(),
            post: vi.fn(),
        }
    }
})

describe('vulnService.js', () => {

    it('getVulns calls apiClient.get with default params when empty', async () => {
        const mockResponse = { data: [] }
        apiClient.get.mockResolvedValueOnce(mockResponse)

        const result = await vulnService.getVulns()

        expect(apiClient.get).toHaveBeenCalledWith('/vulns', {
            params: {}
        })
        expect(result).toEqual(mockResponse)
    })

    it('getVulns calls apiClient.get with specific params', async () => {
        const mockResponse = { data: [] }
        apiClient.get.mockResolvedValueOnce(mockResponse)

        const result = await vulnService.getVulns({ limit: 50, connectionId: 2 })

        expect(apiClient.get).toHaveBeenCalledWith('/vulns', {
            params: {
                limit: 50,
                connection_id: 2,
            }
        })
        expect(result).toEqual(mockResponse)
    })

    it('getVulns maps multi-value filters, score range, sorting and pagination', async () => {
        apiClient.get.mockResolvedValueOnce({ data: [] })

        await vulnService.getVulns({
            page: 2,
            limit: 25,
            agent_name: ['host-a', 'host-b'],
            cve_id: ['CVE-2026-0001'],
            package_name: ['curl'],
            severity: ['Critical', 'High'],
            score_min: 5,
            score_max: 9.5,
            sort_key: 'score_base',
            sort_order: 'desc',
        })

        expect(apiClient.get).toHaveBeenCalledWith('/vulns', {
            params: {
                page: 2,
                limit: 25,
                agent_name: ['host-a', 'host-b'],
                cve_id: ['CVE-2026-0001'],
                package_name: ['curl'],
                severity: ['Critical', 'High'],
                score_min: 5,
                score_max: 9.5,
                sort_key: 'score_base',
                sort_order: 'desc',
            }
        })
    })

    it('getVulns omits empty arrays and empty score strings', async () => {
        apiClient.get.mockResolvedValueOnce({ data: [] })

        await vulnService.getVulns({
            agent_name: [],
            severity: [],
            score_min: '',
            score_max: '',
        })

        expect(apiClient.get).toHaveBeenCalledWith('/vulns', { params: {} })
    })

    it('getVulns keeps score_min of 0 (falsy but valid)', async () => {
        apiClient.get.mockResolvedValueOnce({ data: [] })

        await vulnService.getVulns({ score_min: 0 })

        expect(apiClient.get).toHaveBeenCalledWith('/vulns', {
            params: { score_min: 0 }
        })
    })

    it('getUniqueFilters calls /vulns/filters without params by default', async () => {
        apiClient.get.mockResolvedValueOnce({ data: {} })

        await vulnService.getUniqueFilters()

        expect(apiClient.get).toHaveBeenCalledWith('/vulns/filters', { params: {} })
    })

    it('getUniqueFilters passes connection_id when provided', async () => {
        apiClient.get.mockResolvedValueOnce({ data: {} })

        await vulnService.getUniqueFilters(3)

        expect(apiClient.get).toHaveBeenCalledWith('/vulns/filters', {
            params: { connection_id: 3 }
        })
    })

    it('getUniqueFilters ignores empty-string connection id', async () => {
        apiClient.get.mockResolvedValueOnce({ data: {} })

        await vulnService.getUniqueFilters('')

        expect(apiClient.get).toHaveBeenCalledWith('/vulns/filters', { params: {} })
    })

    it('syncVulns calls apiClient.post on /vulns/sync-all', async () => {
        const mockResponse = { data: { synced: 10 } }

        apiClient.post.mockResolvedValueOnce(mockResponse)

        const result = await vulnService.syncVulns()

        expect(apiClient.post).toHaveBeenCalledWith('/vulns/sync-all')
        expect(result).toEqual(mockResponse)
    })
})

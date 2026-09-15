// Tests for AutotaskHttpClient.rawRequest — verifies the credential-exfiltration
// guards on the user-callable raw passthrough escape hatch.

import { AutotaskHttpClient } from '../src/services/autotask-http';
import { _resetZoneUrlCache } from '../src/utils/config';

describe('AutotaskHttpClient.rawRequest security guards', () => {
  const logger = {
    info: jest.fn(),
    error: jest.fn(),
    debug: jest.fn(),
    warn: jest.fn(),
  };

  // Pre-set apiUrl so baseUrl() resolves without a network call.
  const make = () =>
    new AutotaskHttpClient(
      'user@example.com',
      'secret',
      'integration-code',
      'https://webservices2.autotask.net/ATServicesRest/',
      logger as any
    );

  beforeEach(() => {
    _resetZoneUrlCache();
    Object.values(logger).forEach((m: any) => m.mockReset?.());
  });

  it.each([
    ['absolute URL', 'https://attacker.example.com/x'],
    ['protocol-relative URL', '//attacker.example.com/x'],
    ['embedded scheme', '/Companies/foo://bar'],
    ['backslash injection', '/Companies\\evil'],
    ['path traversal', '/Companies/../../etc/passwd'],
    ['empty path', ''],
    ['relative path without leading slash', 'Companies/175'],
  ])('rejects %s', async (_label, badPath) => {
    const client = make();
    await expect(client.rawRequest('GET', badPath)).rejects.toThrow();
  });

  it('rejects non-allowlisted HTTP methods', async () => {
    const client = make();
    await expect(client.rawRequest('OPTIONS' as any, '/Companies/1')).rejects.toThrow(/method must be one of/);
    await expect(client.rawRequest('TRACE' as any, '/Companies/1')).rejects.toThrow(/method must be one of/);
  });

  it('accepts a valid relative path and dispatches to the resolved zone host', async () => {
    const client = make();
    const fetchMock = jest
      .spyOn(global, 'fetch' as any)
      .mockResolvedValue({
        ok: true,
        status: 200,
        text: async () => JSON.stringify({ ok: true }),
      } as any);

    try {
      const res = await client.rawRequest<any>('GET', '/Companies/175', undefined, { includeFields: 'id,name' });
      expect(res).toEqual({ ok: true });
      expect(fetchMock).toHaveBeenCalledTimes(1);
      const calledUrl = (fetchMock.mock.calls[0] as any)[0] as string;
      expect(calledUrl.startsWith('https://webservices2.autotask.net/')).toBe(true);
      expect(calledUrl).toContain('/Companies/175');
      expect(calledUrl).toContain('includeFields=id%2Cname');
    } finally {
      fetchMock.mockRestore();
    }
  });
});

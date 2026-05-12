import { getPanAadhaarLinkStatusFromSandboxPayload } from './validation';

describe('getPanAadhaarLinkStatusFromSandboxPayload', () => {
  it('returns linked when aadhaar_seeding_status is y', () => {
    expect(
      getPanAadhaarLinkStatusFromSandboxPayload({
        data: { aadhaar_seeding_status: 'y' }
      })
    ).toBe('linked');
    expect(
      getPanAadhaarLinkStatusFromSandboxPayload({
        data: { aadhaar_seeding_status: 'Y' }
      })
    ).toBe('linked');
  });

  it('returns linked when status is valid', () => {
    expect(
      getPanAadhaarLinkStatusFromSandboxPayload({
        data: { status: 'valid' }
      })
    ).toBe('linked');
  });

  it('returns not-linked when neither condition matches', () => {
    expect(
      getPanAadhaarLinkStatusFromSandboxPayload({
        data: { aadhaar_seeding_status: 'n', status: 'invalid' }
      })
    ).toBe('not-linked');
  });

  it('reads fields from root when data is absent', () => {
    expect(
      getPanAadhaarLinkStatusFromSandboxPayload({
        aadhaar_seeding_status: 'y'
      } as Record<string, unknown>)
    ).toBe('linked');
  });

  it('returns not-linked for null or non-object', () => {
    expect(getPanAadhaarLinkStatusFromSandboxPayload(null)).toBe('not-linked');
    expect(getPanAadhaarLinkStatusFromSandboxPayload(undefined)).toBe(
      'not-linked'
    );
  });
});

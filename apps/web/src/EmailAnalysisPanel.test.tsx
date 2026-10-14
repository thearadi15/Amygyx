import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import EmailAnalysisPanel from './EmailAnalysisPanel';

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

const suspiciousAnalysis = {
  result: 'suspicious_indicators',
  ruleset_version: 'email-rules-v1',
  sender_domain: 'example.test',
  return_path_domain: null,
  reply_to_domain: 'lookalike.test',
  urls: [{ scheme: 'https', host: '192.0.2.10', is_ip_literal: true }],
  urls_truncated: false,
  authentication_results: [{ mechanism: 'spf', result: 'fail' }],
  authentication_results_source: 'unverified_message_header',
  indicators: [
    {
      rule_id: 'email.reply-to-domain-mismatch',
      description: 'The Reply-To domain differs from the From domain.',
      severity: 'medium',
      evidence: { sender_domain: 'example.test', reply_to_domain: 'lookalike.test' },
    },
  ],
  finding_id: 'finding-123',
};

describe('EmailAnalysisPanel', () => {
  it('requires an access token and a bounded .eml file before sending', async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal('fetch', fetchMock);
    render(<EmailAnalysisPanel />);

    fireEvent.click(screen.getByRole('button', { name: /analyze message/i }));
    expect(screen.getByRole('alert')).toHaveTextContent(/provide an api access token/i);

    fireEvent.change(screen.getByLabelText(/api access token/i), {
      target: { value: 'provider-token' },
    });
    fireEvent.click(screen.getByRole('button', { name: /analyze message/i }));
    expect(screen.getByRole('alert')).toHaveTextContent(/choose an \.eml message/i);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('posts the message with a bearer token and renders sanitized results', async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => suspiciousAnalysis,
    });
    vi.stubGlobal('fetch', fetchMock);
    render(<EmailAnalysisPanel />);

    fireEvent.change(screen.getByLabelText(/api access token/i), {
      target: { value: 'provider-token' },
    });
    const message = new File(
      ['From: Executive <private@example.test>\r\n\r\nhttp://192.0.2.10/private?token=secret'],
      'sample.eml',
      { type: 'message/rfc822' },
    );
    fireEvent.change(screen.getByLabelText(/email message file/i), {
      target: { files: [message] },
    });
    fireEvent.click(screen.getByRole('button', { name: /analyze message/i }));

    await screen.findByRole('heading', { name: /suspicious indicators found/i });
    expect(fetchMock).toHaveBeenCalledWith(
      'http://127.0.0.1:8000/email/analyze',
      expect.objectContaining({
        method: 'POST',
        headers: {
          Authorization: 'Bearer provider-token',
          'Content-Type': 'application/octet-stream',
        },
        body: message,
      }),
    );
    expect(screen.getByText(/authentication-results are unverified/i)).toBeInTheDocument();
    expect(screen.getByText('https://192.0.2.10')).toBeInTheDocument();
    expect(screen.queryByText(/private\?token=secret/i)).not.toBeInTheDocument();
    expect(screen.getByText(/shared finding created: finding-123/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/api access token/i)).toHaveValue('');
  });

  it('does not send non-eml files or files larger than one MiB', async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal('fetch', fetchMock);
    render(<EmailAnalysisPanel />);
    fireEvent.change(screen.getByLabelText(/api access token/i), {
      target: { value: 'provider-token' },
    });

    fireEvent.change(screen.getByLabelText(/email message file/i), {
      target: {
        files: [new File(['contents'], 'sample.txt', { type: 'text/plain' })],
      },
    });
    fireEvent.click(screen.getByRole('button', { name: /analyze message/i }));
    expect(screen.getByRole('alert')).toHaveTextContent(/\.eml extension/i);

    fireEvent.change(screen.getByLabelText(/email message file/i), {
      target: {
        files: [new File([new Uint8Array(1_048_577)], 'oversized.eml')],
      },
    });
    fireEvent.click(screen.getByRole('button', { name: /analyze message/i }));
    expect(screen.getByRole('alert')).toHaveTextContent(/exceeds the 1 mib/i);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('surfaces API authentication/configuration errors and allows clearing state', async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: false,
      status: 503,
      json: async () => ({ detail: 'Authentication provider is not configured.' }),
    });
    vi.stubGlobal('fetch', fetchMock);
    render(<EmailAnalysisPanel />);

    fireEvent.change(screen.getByLabelText(/api access token/i), {
      target: { value: 'provider-token' },
    });
    fireEvent.change(screen.getByLabelText(/email message file/i), {
      target: { files: [new File(['From: user@example.test'], 'sample.eml')] },
    });
    fireEvent.click(screen.getByRole('button', { name: /analyze message/i }));

    expect(await screen.findByRole('alert')).toHaveTextContent(
      /authentication provider is not configured/i,
    );
    fireEvent.click(screen.getByRole('button', { name: /clear message and results/i }));
    await waitFor(() => {
      expect(screen.queryByRole('alert')).not.toBeInTheDocument();
    });
    expect(screen.getByLabelText(/email message file/i)).toHaveValue('');
  });

  it('rejects a successful response that violates the response contract', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => ({ result: 'success' }),
      }),
    );
    render(<EmailAnalysisPanel />);

    fireEvent.change(screen.getByLabelText(/api access token/i), {
      target: { value: 'provider-token' },
    });
    fireEvent.change(screen.getByLabelText(/email message file/i), {
      target: { files: [new File(['From: user@example.test'], 'sample.eml')] },
    });
    fireEvent.click(screen.getByRole('button', { name: /analyze message/i }));

    expect(await screen.findByRole('alert')).toHaveTextContent(/unexpected email analysis response/i);
  });
});

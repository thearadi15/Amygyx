import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import App from './App';

beforeEach(() => {
  vi.spyOn(window, 'scrollTo').mockImplementation(() => {});
  window.location.hash = '/overview';
});

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

describe('App navigation', () => {
  it('keeps overview focused and exposes separate workspace navigation', () => {
    render(<App />);

    expect(screen.getByRole('heading', { name: /AMYGYX AI-Powered Cyber Intelligence/i })).toBeInTheDocument();
    expect(screen.getByText('Sense the Threat. Reveal the Truth.')).toBeInTheDocument();
    expect(screen.getByRole('navigation', { name: /primary/i })).toBeInTheDocument();
    expect(screen.getByRole('complementary', { name: /platform navigation/i })).toBeInTheDocument();
    expect(screen.getByRole('link', { name: /capability library/i })).toHaveAttribute('href', '#/capabilities');
    expect(screen.queryByRole('heading', { name: /tenant findings/i })).not.toBeInTheDocument();
    expect(screen.queryByRole('heading', { name: /email threat analysis/i })).not.toBeInTheDocument();
    expect(screen.getAllByRole('link', { name: /email analysis/i })).toHaveLength(1);
    expect(screen.getAllByText(/no live telemetry/i).length).toBeGreaterThan(0);
  });

  it('filters the capability library and opens one dedicated analyzer page', async () => {
    window.location.hash = '/capabilities';
    render(<App />);

    expect(screen.getByRole('heading', { name: /all analysis workspaces/i })).toBeInTheDocument();
    const filters = within(screen.getByRole('group', { name: /filter capabilities/i }));
    fireEvent.click(filters.getByRole('button', { name: /filter by risk & assurance/i }));
    expect(screen.getByText(/3 profiles/i)).toBeInTheDocument();

    fireEvent.click(filters.getByRole('button', { name: /filter by all capabilities/i }));
    fireEvent.change(screen.getByRole('searchbox', { name: /search capabilities/i }), {
      target: { value: 'CCTV' },
    });
    expect(screen.getByText(/1 profiles/i)).toBeInTheDocument();
    fireEvent.click(screen.getByRole('link', { name: /CCTV event metadata/i }));

    await waitFor(() => {
      expect(screen.getByRole('heading', { name: /CCTV event metadata/i })).toBeInTheDocument();
    });
    expect(screen.getByRole('heading', { name: /CCTV event export review/i })).toBeInTheDocument();
    expect(screen.queryByRole('heading', { name: /tenant findings/i })).not.toBeInTheDocument();
    expect(window.location.hash).toBe('#/video');
  });

  it('opens findings and incident operations as separate pages', async () => {
    render(<App />);

    fireEvent.click(screen.getByRole('link', { name: /^findings$/i }));
    await waitFor(() => {
      expect(screen.getByRole('heading', { name: /tenant findings/i })).toBeInTheDocument();
    });
    expect(screen.queryByRole('heading', { name: /^incidents$/i })).not.toBeInTheDocument();

    fireEvent.click(screen.getByRole('link', { name: /^incidents$/i }));
    await waitFor(() => {
      expect(screen.getByRole('heading', { name: /^incidents$/i })).toBeInTheDocument();
    });
    expect(screen.queryByRole('heading', { name: /tenant findings/i })).not.toBeInTheDocument();
  });

  it('shows production connector requirements without implying any are connected', async () => {
    render(<App />);

    fireEvent.click(screen.getByRole('link', { name: /integrations 0 connected/i }));
    await waitFor(() => {
      expect(screen.getByRole('heading', { name: /integration readiness/i })).toBeInTheDocument();
    });
    expect(screen.getByText(/no live integrations are connected/i)).toBeInTheDocument();
    expect(screen.getAllByText(/telephony/i).length).toBeGreaterThan(0);
    expect(screen.getByText(/NetFlow\/IPFIX\/sFlow/i)).toBeInTheDocument();
    expect(screen.getAllByText(/NOT CONNECTED/i).length).toBeGreaterThan(0);
  });
});

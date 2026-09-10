"""Visual Explorer

Analyzes the DOM to understand UI structure before attacking.
Maps buttons, forms, tabs, modals, menus, infinite scroll, upload widgets.
Identifies attack surfaces from the UI perspective.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class ButtonInfo:
    text: str
    selector: str
    action: str = ""
    requires_auth: bool = False


@dataclass
class FormInfo:
    action: str
    method: str
    fields: list[dict[str, Any]] = field(default_factory=list)
    upload_enabled: bool = False


@dataclass
class NavInfo:
    links: list[dict[str, str]] = field(default_factory=list)
    tabs: list[str] = field(default_factory=list)
    menus: list[str] = field(default_factory=list)


class VisualExplorer:
    """Analyzes DOM structure to find attack surfaces."""

    def __init__(self, browser_tool):
        self.browser = browser_tool

    async def explore(self) -> dict[str, Any]:
        """Full UI exploration of current page."""
        if not self.browser._page:
            return {}

        return await self.browser._page.evaluate("""
            () => {
                const result = {
                    buttons: [],
                    forms: [],
                    navigation: { links: [], tabs: [], menus: [] },
                    modals: [],
                    infinite_scroll: false,
                    upload_widgets: [],
                    data_tables: [],
                    search_widgets: [],
                    date_filters: [],
                    pagination: null,
                };

                // Buttons
                document.querySelectorAll('button, [role="button"], input[type="submit"]').forEach(el => {
                    const text = el.textContent?.trim() || el.value || '';
                    if (text) {
                        result.buttons.push({
                            text: text.substring(0, 100),
                            selector: el.id ? '#' + el.id : el.tagName,
                            disabled: el.disabled,
                        });
                    }
                });

                // Forms
                document.querySelectorAll('form').forEach(el => {
                    const fields = [];
                    el.querySelectorAll('input, select, textarea').forEach(f => {
                        fields.push({
                            name: f.name,
                            type: f.type || f.tagName.toLowerCase(),
                            required: f.required,
                            accept: f.accept || '',
                        });
                    });
                    result.forms.push({
                        action: el.action,
                        method: el.method,
                        fields: fields,
                        has_upload: fields.some(f => f.type === 'file' || f.accept.includes('/')),
                    });
                });

                // Navigation
                document.querySelectorAll('nav a, [role="navigation"] a').forEach(el => {
                    result.navigation.links.push({
                        text: el.textContent?.trim()?.substring(0, 50) || '',
                        href: el.href,
                    });
                });

                document.querySelectorAll('[role="tab"], .tab, [class*="tab"]').forEach(el => {
                    const text = el.textContent?.trim();
                    if (text) result.navigation.tabs.push(text.substring(0, 50));
                });

                // Modals
                document.querySelectorAll('[role="dialog"], .modal, [class*="modal"]').forEach(el => {
                    result.modals.push({
                        visible: el.offsetParent !== null,
                        has_form: el.querySelector('form') !== null,
                        text: el.textContent?.trim()?.substring(0, 200) || '',
                    });
                });

                // Infinite scroll detection
                const lastEl = document.querySelector('[class*="infinite"], [class*="load-more"], [data-infinite]');
                result.infinite_scroll = lastEl !== null || document.querySelector('[class*="scroll"]')?.scrollHeight > 1000;

                // Upload widgets
                document.querySelectorAll('input[type="file"], [class*="upload"], [class*="drop"]').forEach(el => {
                    result.upload_widgets.push({
                        accept: el.accept || '',
                        multiple: el.multiple || false,
                    });
                });

                // Data tables
                document.querySelectorAll('table').forEach(el => {
                    const headers = Array.from(el.querySelectorAll('th')).map(th => th.textContent?.trim());
                    result.data_tables.push({
                        headers: headers,
                        rows: el.querySelectorAll('tr').length,
                    });
                });

                // Search widgets
                document.querySelectorAll('input[type="search"], [class*="search"], [placeholder*="search" i]').forEach(el => {
                    result.search_widgets.push({
                        type: el.type,
                        placeholder: el.placeholder || '',
                    });
                });

                // Date filters
                document.querySelectorAll('input[type="date"], [class*="date-picker"], [class*="datepicker"]').forEach(() => {
                    result.date_filters.push(true);
                });

                // Pagination
                const pagination = document.querySelector('[class*="pagination"], [role="navigation"][aria-label*="page"]');
                if (pagination) {
                    const pages = pagination.querySelectorAll('a, button');
                    result.pagination = {
                        pages: pages.length,
                        last_page: pages[pages.length - 1]?.textContent?.trim(),
                    };
                }

                return result;
            }
        """)

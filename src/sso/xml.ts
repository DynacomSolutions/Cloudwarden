import {
  DOMImplementation,
  DOMParser,
  type Document,
  type Element,
  type Node,
  XMLSerializer,
} from '@xmldom/xmldom'
import { setNodeDependencies } from 'xml-core'
import { SsoError } from './errors'

/**
 * XML plumbing for SAML: a hardened parser (no DTDs, so no entity expansion or external
 * references), namespace-aware element lookup and the DOM implementation `xmldsigjs` uses.
 */

// `xml-core` (under `xmldsigjs`) looks these up when the platform has no DOM, as on Workers.
setNodeDependencies({ DOMParser, XMLSerializer, DOMImplementation })

export const NS = {
  samlp: 'urn:oasis:names:tc:SAML:2.0:protocol',
  saml: 'urn:oasis:names:tc:SAML:2.0:assertion',
  ds: 'http://www.w3.org/2000/09/xmldsig#',
  xenc: 'http://www.w3.org/2001/04/xmlenc#',
  xenc11: 'http://www.w3.org/2009/xmlenc11#',
  md: 'urn:oasis:names:tc:SAML:2.0:metadata',
} as const

export const MAX_XML_BYTES = 512 * 1024

export type { Document, Element }

/** Parses untrusted XML. Rejects doctypes, processing instructions other than the declaration and any parser error. */
export function parseXml(xml: string): Document {
  if (xml.length > MAX_XML_BYTES) throw new SsoError('The SAML message is too large.')
  if (/<!DOCTYPE|<!ENTITY/i.test(xml)) throw new SsoError('The SAML message contains a DTD.')
  if (/<\?(?!xml\s)[^>]*\?>/i.test(xml.replace(/^﻿/, ''))) {
    throw new SsoError('The SAML message contains processing instructions.')
  }
  let doc: Document
  try {
    doc = new DOMParser({
      onError: (level, message) => {
        if (level !== 'warning') throw new Error(message)
      },
    }).parseFromString(xml, 'text/xml')
  } catch (err) {
    throw new SsoError('The SAML message is not well-formed XML.', err)
  }
  if (!doc.documentElement) throw new SsoError('The SAML message is empty.')
  return doc
}

export const serialize = (node: Node) => new XMLSerializer().serializeToString(node)

const isElement = (n: Node | null | undefined): n is Element => n?.nodeType === 1

/** Direct element children with the given namespace and local name. */
export function children(parent: Element, ns: string, local: string): Element[] {
  const out: Element[] = []
  for (let n = parent.firstChild; n; n = n.nextSibling) {
    if (isElement(n) && n.namespaceURI === ns && n.localName === local) out.push(n)
  }
  return out
}

/** The single direct child, or null. More than one is an error. */
export function child(parent: Element, ns: string, local: string): Element | null {
  const found = children(parent, ns, local)
  if (found.length > 1) throw new SsoError(`The SAML message has more than one ${local}.`)
  return found[0] ?? null
}

/** Every descendant element with the namespace and local name. */
export function descendants(root: Document | Element, ns: string, local: string): Element[] {
  const list = root.getElementsByTagNameNS(ns, local)
  const out: Element[] = []
  for (let i = 0; i < list.length; i++) {
    const el = list.item(i)
    if (el) out.push(el)
  }
  return out
}

export const text = (el: Element | null | undefined): string => (el?.textContent ?? '').trim()

/** Number of elements anywhere in the document carrying `id` in an ID, Id or id attribute. */
export function countIds(doc: Document, id: string): number {
  let count = 0
  const walk = (n: Node) => {
    if (isElement(n)) {
      for (const name of ['ID', 'Id', 'id']) if (n.getAttribute(name) === id) count++
    }
    for (let c = n.firstChild; c; c = c.nextSibling) walk(c)
  }
  walk(doc)
  return count
}

/** Escapes text for element content and attribute values. */
export const esc = (s: string) =>
  s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;')

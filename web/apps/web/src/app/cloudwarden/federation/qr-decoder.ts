// Cloudwarden: reads one QR code from an image source (web/NOTICE.md). The browser's
// BarcodeDetector is used when it exists; otherwise jsQR (Apache-2.0), loaded on first use.

interface DetectedBarcode {
  rawValue: string;
}
interface BarcodeDetectorLike {
  detect(source: CanvasImageSource): Promise<DetectedBarcode[]>;
}
type BarcodeDetectorCtor = new (opts: {
  formats: string[];
}) => BarcodeDetectorLike;

export type DecodableSource = HTMLVideoElement | HTMLImageElement;

const detectorCtor = (): BarcodeDetectorCtor | null =>
  (globalThis as { BarcodeDetector?: BarcodeDetectorCtor }).BarcodeDetector ??
  null;

export const hasNativeDetector = (): boolean => detectorCtor() !== null;

function sizeOf(source: DecodableSource): [number, number] {
  return source instanceof HTMLVideoElement
    ? [source.videoWidth, source.videoHeight]
    : [source.naturalWidth, source.naturalHeight];
}

async function jsQrDecode(source: DecodableSource): Promise<string | null> {
  const [w, h] = sizeOf(source);
  if (!w || !h) {
    return null;
  }
  // Frames are scaled down: a low-density QR needs no more, and it keeps the decoder quick.
  const scale = Math.min(1, 800 / Math.max(w, h));
  const canvas = document.createElement("canvas");
  canvas.width = Math.round(w * scale);
  canvas.height = Math.round(h * scale);
  const ctx = canvas.getContext("2d", { willReadFrequently: true });
  if (!ctx) {
    return null;
  }
  ctx.drawImage(source, 0, 0, canvas.width, canvas.height);
  const data = ctx.getImageData(0, 0, canvas.width, canvas.height);
  const { default: jsQR } = await import("jsqr");
  return jsQR(data.data, data.width, data.height)?.data ?? null;
}

/** Text of the first QR code found, or null. Never throws. */
export async function decodeQr(
  source: DecodableSource,
): Promise<string | null> {
  const Ctor = detectorCtor();
  if (Ctor) {
    try {
      const found = await new Ctor({ formats: ["qr_code"] }).detect(source);
      if (found.length > 0 && found[0].rawValue) {
        return found[0].rawValue;
      }
      return null;
    } catch {
      // Fall through to the software decoder.
    }
  }
  try {
    return await jsQrDecode(source);
  } catch {
    return null;
  }
}

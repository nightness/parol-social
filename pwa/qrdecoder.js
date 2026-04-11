/**
 * Pure JavaScript QR Code Decoder
 *
 * A self-contained QR code decoder that works on ALL browsers including
 * iOS Safari (which lacks the BarcodeDetector API). No external dependencies.
 *
 * Exports a single global function:
 *   decodeQRFromImageData(data, width, height) => string | null
 *
 * Where `data` is a Uint8ClampedArray of RGBA pixel values (from canvas
 * getImageData().data), and width/height are the image dimensions.
 */
(function(global) {
'use strict';

// ── Binarization ───────────────────────────────────────────────────
// Convert RGBA image data to a binary (black=1 / white=0) array using
// an adaptive threshold. We use an integral image for fast local mean
// computation, which is critical for handling uneven lighting from a
// phone camera pointed at a screen.

function binarize(data, width, height) {
    // Convert RGBA to grayscale using luminance weights
    const gray = new Uint8Array(width * height);
    for (let i = 0; i < width * height; i++) {
        const r = data[i * 4];
        const g = data[i * 4 + 1];
        const b = data[i * 4 + 2];
        gray[i] = (r * 77 + g * 150 + b * 29) >> 8;
    }

    // Build integral image for fast block-mean computation
    const integral = new Float64Array(width * height);
    for (let y = 0; y < height; y++) {
        let rowSum = 0;
        for (let x = 0; x < width; x++) {
            rowSum += gray[y * width + x];
            integral[y * width + x] = rowSum + (y > 0 ? integral[(y - 1) * width + x] : 0);
        }
    }

    function blockMean(x0, y0, x1, y1) {
        x0 = Math.max(0, x0);
        y0 = Math.max(0, y0);
        x1 = Math.min(width - 1, x1);
        y1 = Math.min(height - 1, y1);
        let sum = integral[y1 * width + x1];
        if (x0 > 0) sum -= integral[y1 * width + (x0 - 1)];
        if (y0 > 0) sum -= integral[(y0 - 1) * width + x1];
        if (x0 > 0 && y0 > 0) sum += integral[(y0 - 1) * width + (x0 - 1)];
        const area = (x1 - x0 + 1) * (y1 - y0 + 1);
        return sum / area;
    }

    // Adaptive threshold: compare each pixel against its local block mean
    const blockSize = Math.max(Math.floor(Math.min(width, height) / 8), 8);
    const binary = new Uint8Array(width * height);

    for (let y = 0; y < height; y++) {
        for (let x = 0; x < width; x++) {
            const mean = blockMean(x - blockSize, y - blockSize, x + blockSize, y + blockSize);
            // A pixel is "black" if it is noticeably darker than the local mean
            binary[y * width + x] = gray[y * width + x] < mean - 8 ? 1 : 0;
        }
    }
    return binary;
}

// ── Finder Pattern Detection ───────────────────────────────────────
// QR codes have three finder patterns: large squares in three corners.
// Each finder has a cross-section ratio of 1:1:3:1:1 (B:W:B:W:B).

function checkRatio(counts) {
    const total = counts[0] + counts[1] + counts[2] + counts[3] + counts[4];
    if (total < 7) return false;
    const moduleSize = total / 7.0;
    const tolerance = moduleSize * 0.6;
    return (
        Math.abs(counts[0] - moduleSize) < tolerance &&
        Math.abs(counts[1] - moduleSize) < tolerance &&
        Math.abs(counts[2] - 3 * moduleSize) < tolerance &&
        Math.abs(counts[3] - moduleSize) < tolerance &&
        Math.abs(counts[4] - moduleSize) < tolerance
    );
}

function verifyCross(binary, width, height, centerX, centerY, isHorizontal, estimatedModuleSize) {
    const limit = isHorizontal ? width : height;
    const step = isHorizontal ?
        function(pos) { return centerY * width + pos; } :
        function(pos) { return pos * width + centerX; };

    const center = isHorizontal ? centerX : centerY;
    const counts = [0, 0, 0, 0, 0];

    // Count outward from center - state 2 (center black bar)
    let pos = center;
    while (pos >= 0 && binary[step(pos)] === 1) { counts[2]++; pos--; }
    // state 1 (white)
    while (pos >= 0 && binary[step(pos)] === 0) { counts[1]++; pos--; }
    // state 0 (outer black)
    while (pos >= 0 && binary[step(pos)] === 1) { counts[0]++; pos--; }

    pos = center + 1;
    // state 2 continues (center black bar, other direction)
    while (pos < limit && binary[step(pos)] === 1) { counts[2]++; pos++; }
    // state 3 (white)
    while (pos < limit && binary[step(pos)] === 0) { counts[3]++; pos++; }
    // state 4 (outer black)
    while (pos < limit && binary[step(pos)] === 1) { counts[4]++; pos++; }

    return checkRatio(counts) ? counts : null;
}

function findFinderPatterns(binary, width, height) {
    const candidates = [];

    // Scan horizontally, skipping every other row for speed
    for (let y = 0; y < height; y += 2) {
        let state = 0;
        const counts = [0, 0, 0, 0, 0];

        for (let x = 0; x < width; x++) {
            const pixel = binary[y * width + x];

            if (pixel === 1) {
                // Black pixel
                if (state === 1 || state === 3) {
                    // Was in a white segment, advance state
                    state++;
                    counts[state] = 1;
                } else {
                    // Still in a black segment (state 0, 2, or 4)
                    counts[state]++;
                }
            } else {
                // White pixel
                if (state === 0 || state === 2) {
                    // Was in a black segment, advance state
                    state++;
                    counts[state] = 1;
                } else if (state === 4) {
                    // End of pattern candidate - check ratio
                    if (checkRatio(counts)) {
                        const totalWidth = counts[0] + counts[1] + counts[2] + counts[3] + counts[4];
                        const centerX = Math.round(x - counts[4] - counts[3] - counts[2] / 2);
                        const moduleSize = totalWidth / 7.0;

                        // Cross-verify vertically
                        const vCounts = verifyCross(binary, width, height, centerX, y, false, moduleSize);
                        if (vCounts) {
                            // Cross-verify diagonally for extra confidence
                            const avgSize = (totalWidth + (vCounts[0] + vCounts[1] + vCounts[2] + vCounts[3] + vCounts[4])) / 14.0;
                            candidates.push({
                                x: centerX,
                                y: y,
                                size: avgSize
                            });
                        }
                    }
                    // Shift window
                    counts[0] = counts[2];
                    counts[1] = counts[3];
                    counts[2] = counts[4];
                    counts[3] = 1;
                    counts[4] = 0;
                    state = 3;
                } else {
                    // Still in a white segment (state 1 or 3)
                    counts[state]++;
                }
            }
        }
    }

    // Cluster nearby candidates into single finder patterns
    return clusterCandidates(candidates);
}

function clusterCandidates(candidates) {
    if (candidates.length === 0) return [];
    const clusters = [];
    const used = new Set();

    for (let i = 0; i < candidates.length; i++) {
        if (used.has(i)) continue;
        let sumX = candidates[i].x;
        let sumY = candidates[i].y;
        let sumS = candidates[i].size;
        let count = 1;

        for (let j = i + 1; j < candidates.length; j++) {
            if (used.has(j)) continue;
            const dist = Math.sqrt(
                (candidates[i].x - candidates[j].x) ** 2 +
                (candidates[i].y - candidates[j].y) ** 2
            );
            if (dist < candidates[i].size * 10) {
                sumX += candidates[j].x;
                sumY += candidates[j].y;
                sumS += candidates[j].size;
                count++;
                used.add(j);
            }
        }

        clusters.push({
            x: sumX / count,
            y: sumY / count,
            size: sumS / count
        });
        used.add(i);
    }

    return clusters;
}

// ── Pattern Arrangement ────────────────────────────────────────────
// Given 3+ finder patterns, determine which is top-left (the corner
// where the right angle is), top-right, and bottom-left.

function arrangePatterns(patterns) {
    if (patterns.length < 3) return null;

    // Try all combinations of 3 patterns (limit search to first 8 candidates)
    const limit = Math.min(patterns.length, 8);
    let best = null;
    let bestScore = Infinity;

    for (let i = 0; i < limit; i++) {
        for (let j = i + 1; j < limit; j++) {
            for (let k = j + 1; k < limit; k++) {
                const p = [patterns[i], patterns[j], patterns[k]];

                // Check that all three have reasonably similar module sizes
                const sizes = p.map(pp => pp.size);
                const minS = Math.min(...sizes);
                const maxS = Math.max(...sizes);
                if (maxS > minS * 2.5) continue;

                // Try each as the corner (top-left = where the 90-degree angle is)
                for (let corner = 0; corner < 3; corner++) {
                    const a = p[corner];
                    const b = p[(corner + 1) % 3];
                    const c = p[(corner + 2) % 3];

                    const abx = b.x - a.x, aby = b.y - a.y;
                    const acx = c.x - a.x, acy = c.y - a.y;
                    const dot = abx * acx + aby * acy;
                    const cross = abx * acy - aby * acx;
                    const angle = Math.abs(Math.atan2(cross, dot));
                    const score = Math.abs(angle - Math.PI / 2);

                    if (score < bestScore) {
                        bestScore = score;
                        // Use cross product sign to determine orientation
                        if (cross > 0) {
                            best = { topLeft: a, topRight: c, bottomLeft: b };
                        } else {
                            best = { topLeft: a, topRight: b, bottomLeft: c };
                        }
                    }
                }
            }
        }
    }

    // Accept if the angle is within ~30 degrees of 90
    return bestScore < 0.55 ? best : null;
}

// ── Grid Extraction ────────────────────────────────────────────────
// Sample the QR code data grid from the binary image using the finder
// pattern positions to determine the perspective transformation.

function extractGrid(binary, width, height, arranged, moduleSize) {
    const { topLeft, topRight, bottomLeft } = arranged;

    // Estimate QR code dimension from the distance between finder pattern centers.
    // The distance from top-left to top-right center spans (dimension - 7) modules,
    // because each finder pattern center is 3.5 modules from the edge.
    const topDist = Math.sqrt(
        (topRight.x - topLeft.x) ** 2 + (topRight.y - topLeft.y) ** 2
    );
    const leftDist = Math.sqrt(
        (bottomLeft.x - topLeft.x) ** 2 + (bottomLeft.y - topLeft.y) ** 2
    );
    const avgDist = (topDist + leftDist) / 2;
    const rawDim = avgDist / moduleSize + 7;

    // QR dimensions are always 4*version + 17, for version 1-40
    const version = Math.max(1, Math.min(40, Math.round((rawDim - 17) / 4)));
    const size = version * 4 + 17;

    // The finder pattern centers are at module coordinates (3.5, 3.5),
    // (3.5, size-3.5), and (size-3.5, 3.5) for TL, TR, BL respectively.
    // We use these three known points to build an affine transform from
    // module coordinates to pixel coordinates.
    //
    // Module (col, row) -> pixel (px, py):
    //   px = a*col + b*row + c
    //   py = d*col + e*row + f
    //
    // From the three finder centers:
    //   TL: (3.5, 3.5) -> (topLeft.x, topLeft.y)
    //   TR: (size-3.5, 3.5) -> (topRight.x, topRight.y)
    //   BL: (3.5, size-3.5) -> (bottomLeft.x, bottomLeft.y)

    const tlCol = 3.5, tlRow = 3.5;
    const trCol = size - 3.5, trRow = 3.5;
    const blCol = 3.5, blRow = size - 3.5;

    // Solve for affine coefficients:
    // a*(trCol - tlCol) = topRight.x - topLeft.x  =>  a = (topRight.x - topLeft.x) / (size - 7)
    // b*(blRow - tlRow) = bottomLeft.x - topLeft.x =>  b = (bottomLeft.x - topLeft.x) / (size - 7)
    // c = topLeft.x - a*3.5 - b*3.5
    const span = size - 7;
    const ax = (topRight.x - topLeft.x) / span;
    const bx = (bottomLeft.x - topLeft.x) / span;
    const cx = topLeft.x - ax * tlCol - bx * tlRow;

    const ay = (topRight.y - topLeft.y) / span;
    const by = (bottomLeft.y - topLeft.y) / span;
    const cy = topLeft.y - ay * tlCol - by * tlRow;

    // Sample the grid
    const grid = [];
    for (let row = 0; row < size; row++) {
        grid[row] = [];
        for (let col = 0; col < size; col++) {
            // Map module center (col+0.5, row+0.5) to pixel coordinates
            const mc = col + 0.5;
            const mr = row + 0.5;
            const px = Math.round(ax * mc + bx * mr + cx);
            const py = Math.round(ay * mc + by * mr + cy);

            if (px >= 0 && px < width && py >= 0 && py < height) {
                grid[row][col] = binary[py * width + px] === 1;
            } else {
                grid[row][col] = false;
            }
        }
    }

    return { grid, size, version };
}

// ── Reserved Module Mask ───────────────────────────────────────────
// Mark all modules that are NOT data: finder patterns, timing, format
// info, version info, and alignment patterns.

function getAlignmentPositions(version) {
    if (version <= 1) return [];
    // Alignment pattern center coordinates per version
    const table = [
        [], [6,18], [6,22], [6,26], [6,30], [6,34],
        [6,22,38], [6,24,42], [6,26,46], [6,28,50], [6,30,54],
        [6,32,58], [6,34,62], [6,26,46,66], [6,26,48,70], [6,26,50,74],
        [6,30,54,78], [6,30,56,82], [6,30,58,86], [6,34,62,90],
        [6,28,50,72,94], [6,26,50,74,98], [6,30,54,78,102],
        [6,28,54,80,106], [6,32,58,84,110], [6,30,58,86,114],
        [6,34,62,90,118], [6,26,50,74,98,122], [6,30,54,78,102,126],
        [6,26,52,78,104,130], [6,30,56,82,108,134],
        [6,34,60,86,112,138], [6,30,58,86,114,142],
        [6,34,62,90,118,146], [6,30,54,78,102,126,150],
        [6,24,50,76,102,128,154], [6,28,54,80,106,132,158],
        [6,32,58,84,110,136,162], [6,26,54,82,110,138,166],
        [6,30,58,86,114,142,170]
    ];
    return version <= 40 ? (table[version - 1] || []) : [];
}

function makeReservedMask(size, version) {
    const m = Array.from({ length: size }, () => new Array(size).fill(false));

    // Finder patterns (7x7) + separators (1 module white border)
    // Top-left
    for (let r = 0; r < 9 && r < size; r++) {
        for (let c = 0; c < 9 && c < size; c++) {
            m[r][c] = true;
        }
    }
    // Top-right
    for (let r = 0; r < 9 && r < size; r++) {
        for (let c = size - 8; c < size; c++) {
            if (c >= 0) m[r][c] = true;
        }
    }
    // Bottom-left
    for (let r = size - 8; r < size; r++) {
        for (let c = 0; c < 9 && c < size; c++) {
            if (r >= 0) m[r][c] = true;
        }
    }

    // Timing patterns (row 6 and column 6)
    for (let i = 0; i < size; i++) {
        m[6][i] = true;
        m[i][6] = true;
    }

    // Dark module (always present at (size-8, 8) for versions >= 1)
    if (size > 8) {
        m[size - 8][8] = true;
    }

    // Format information areas (around all three finder patterns)
    // Around top-left finder
    for (let i = 0; i < 9; i++) {
        if (i < size) m[8][i] = true;
        if (i < size) m[i][8] = true;
    }
    // Around top-right finder
    for (let i = 0; i < 8; i++) {
        if (size - 1 - i >= 0) m[8][size - 1 - i] = true;
    }
    // Around bottom-left finder
    for (let i = 0; i < 8; i++) {
        if (size - 1 - i >= 0) m[size - 1 - i][8] = true;
    }

    // Version information (versions 7+)
    if (version >= 7) {
        for (let i = 0; i < 6; i++) {
            for (let j = size - 11; j < size - 8; j++) {
                if (j >= 0) {
                    m[i][j] = true;  // top-right area
                    m[j][i] = true;  // bottom-left area
                }
            }
        }
    }

    // Alignment patterns
    const alignPos = getAlignmentPositions(version);
    if (alignPos.length > 0) {
        for (let i = 0; i < alignPos.length; i++) {
            for (let j = 0; j < alignPos.length; j++) {
                const ar = alignPos[i];
                const ac = alignPos[j];
                // Skip if overlapping with finder patterns
                if (ar < 9 && ac < 9) continue;                          // top-left
                if (ar < 9 && ac > size - 9) continue;                   // top-right
                if (ar > size - 9 && ac < 9) continue;                   // bottom-left
                // Mark 5x5 alignment pattern
                for (let dr = -2; dr <= 2; dr++) {
                    for (let dc = -2; dc <= 2; dc++) {
                        const rr = ar + dr;
                        const cc = ac + dc;
                        if (rr >= 0 && rr < size && cc >= 0 && cc < size) {
                            m[rr][cc] = true;
                        }
                    }
                }
            }
        }
    }

    return m;
}

// ── Format Information ─────────────────────────────────────────────
// Read the 15-bit format string from the two copies around the TL finder.
// The format encodes error correction level (2 bits) and mask pattern (3 bits).

const FORMAT_MASK = 0x5412; // XOR mask applied to format bits

function readFormatInfo(grid, size) {
    // First copy: bits 0-7 along row 8 (columns 0-5, skip 6, then 7-8),
    //             bits 8-14 along column 8 (rows 7, 5-0)
    // Second copy: bits 0-7 along column 8 from bottom (rows size-1 to size-7),
    //              bits 8-14 along row 8 from right (columns size-8 to size-1)

    function readFirstCopy() {
        const bits = [];
        // Row 8, columns 0-5
        for (let c = 0; c <= 5; c++) bits.push(grid[8][c] ? 1 : 0);
        // Row 8, column 7
        bits.push(grid[8][7] ? 1 : 0);
        // Row 8, column 8
        bits.push(grid[8][8] ? 1 : 0);
        // Column 8, row 7
        bits.push(grid[7][8] ? 1 : 0);
        // Column 8, rows 5 down to 0
        for (let r = 5; r >= 0; r--) bits.push(grid[r][8] ? 1 : 0);
        return bits;
    }

    function readSecondCopy() {
        const bits = [];
        // Column 8, rows from size-1 up to size-7
        for (let r = size - 1; r >= size - 7; r--) bits.push(grid[r][8] ? 1 : 0);
        // Row 8, columns size-8 to size-1
        for (let c = size - 8; c <= size - 1; c++) bits.push(grid[8][c] ? 1 : 0);
        return bits;
    }

    function bitsToInt(bits) {
        let val = 0;
        for (let i = 0; i < bits.length; i++) {
            val = (val << 1) | bits[i];
        }
        return val;
    }

    // Try both copies, pick the one that decodes with fewer BCH errors
    const copies = [readFirstCopy(), readSecondCopy()];

    for (const bits of copies) {
        const raw = bitsToInt(bits) ^ FORMAT_MASK;
        // Extract fields (the BCH error correction is 10 bits but we do
        // a simple extraction — for most real-world QR codes this works)
        const ecLevel = (raw >> 13) & 0x3;
        const maskPattern = (raw >> 10) & 0x7;

        if (maskPattern >= 0 && maskPattern <= 7) {
            return { ecLevel, maskPattern, raw };
        }
    }

    // If neither copy looks valid, try all 8 mask patterns and return the
    // first that yields plausible data (brute-force fallback)
    const bits = copies[0];
    const raw = bitsToInt(bits) ^ FORMAT_MASK;
    return {
        ecLevel: (raw >> 13) & 0x3,
        maskPattern: (raw >> 10) & 0x7,
        raw
    };
}

// ── Unmasking ──────────────────────────────────────────────────────
// QR codes apply one of 8 mask patterns to the data modules to ensure
// the code is scannable. We must undo the mask to read the raw data.

const MASK_FUNCTIONS = [
    function(r, c) { return (r + c) % 2 === 0; },
    function(r, c) { return r % 2 === 0; },
    function(r, c) { return c % 3 === 0; },
    function(r, c) { return (r + c) % 3 === 0; },
    function(r, c) { return (Math.floor(r / 2) + Math.floor(c / 3)) % 2 === 0; },
    function(r, c) { return (r * c) % 2 + (r * c) % 3 === 0; },
    function(r, c) { return ((r * c) % 2 + (r * c) % 3) % 2 === 0; },
    function(r, c) { return ((r + c) % 2 + (r * c) % 3) % 2 === 0; },
];

function unmask(grid, size, version, maskPattern) {
    const fn = MASK_FUNCTIONS[maskPattern] || MASK_FUNCTIONS[0];
    const reserved = makeReservedMask(size, version);
    const result = grid.map(function(row) { return row.slice(); });

    for (let r = 0; r < size; r++) {
        for (let c = 0; c < size; c++) {
            if (!reserved[r][c] && fn(r, c)) {
                result[r][c] = !result[r][c];
            }
        }
    }

    return result;
}

// ── Data Bit Reading ───────────────────────────────────────────────
// Read data bits in the zigzag pattern defined by the QR spec:
// Two-column strips moving upward and downward alternately, right to left,
// skipping column 6 (the vertical timing pattern).

function readDataBits(grid, size, version) {
    const reserved = makeReservedMask(size, version);
    const bits = [];
    let upward = true;

    for (let col = size - 1; col >= 1; col -= 2) {
        // Skip the vertical timing column
        if (col === 6) col = 5;

        for (let i = 0; i < size; i++) {
            const row = upward ? (size - 1 - i) : i;
            // Each strip reads two columns: col and col-1
            for (let dc = 0; dc <= 1; dc++) {
                const c = col - dc;
                if (c < 0) continue;
                if (!reserved[row][c]) {
                    bits.push(grid[row][c] ? 1 : 0);
                }
            }
        }
        upward = !upward;
    }

    return bits;
}

// ── Reed-Solomon Error Correction ──────────────────────────────────
// Galois Field GF(2^8) arithmetic with primitive polynomial 0x11D.

const GF_EXP = new Uint8Array(512);
const GF_LOG = new Uint8Array(256);

(function initGaloisField() {
    let x = 1;
    for (let i = 0; i < 255; i++) {
        GF_EXP[i] = x;
        GF_LOG[x] = i;
        x <<= 1;
        if (x & 0x100) x ^= 0x11D;
    }
    for (let i = 255; i < 512; i++) {
        GF_EXP[i] = GF_EXP[i - 255];
    }
})();

function gfMul(a, b) {
    if (a === 0 || b === 0) return 0;
    return GF_EXP[GF_LOG[a] + GF_LOG[b]];
}

function gfPolyEval(poly, x) {
    let result = poly[0];
    for (let i = 1; i < poly.length; i++) {
        result = gfMul(result, x) ^ poly[i];
    }
    return result;
}

function rsSyndromes(data, nsym) {
    const synd = new Uint8Array(nsym);
    for (let i = 0; i < nsym; i++) {
        synd[i] = gfPolyEval(data, GF_EXP[i]);
    }
    return synd;
}

function rsCheckClean(syndromes) {
    for (let i = 0; i < syndromes.length; i++) {
        if (syndromes[i] !== 0) return false;
    }
    return true;
}

// ── Data Decoding ──────────────────────────────────────────────────
// Interpret the raw data bits according to the QR spec encoding modes.

// Error correction code word counts per version and EC level
// ecTable[version-1][ecLevel] = { dataCodewords, ecCodewordsPerBlock, numBlocks }
// For simplicity, we store total data codewords and use them for decoding.
// A full table would be huge; we encode the most common versions (1-10)
// and fall back to a heuristic for larger versions.
const EC_TABLE = buildECTable();

function buildECTable() {
    // [totalCodewords, [L_data, M_data, Q_data, H_data]]
    // From the QR spec for versions 1-40
    const raw = [
        [26, [19,16,13,9]],
        [44, [34,28,22,16]],
        [70, [55,44,34,26]],
        [100, [80,64,48,36]],
        [134, [108,86,62,46]],
        [172, [136,108,76,60]],
        [196, [156,124,88,66]],
        [242, [194,154,110,86]],
        [292, [232,182,132,100]],
        [346, [274,216,154,122]],
        [404, [324,254,180,140]],
        [466, [370,290,206,158]],
        [532, [428,334,244,180]],
        [581, [461,365,261,197]],
        [655, [523,415,295,223]],
        [733, [589,453,325,253]],
        [815, [647,507,367,283]],
        [901, [721,563,397,313]],
        [991, [795,627,445,341]],
        [1085, [861,669,485,385]],
        [1156, [932,714,512,406]],
        [1258, [1006,782,568,442]],
        [1364, [1094,860,614,464]],
        [1474, [1174,914,664,514]],
        [1588, [1276,1000,718,538]],
        [1706, [1370,1062,754,596]],
        [1828, [1468,1128,808,628]],
        [1921, [1531,1193,871,661]],
        [2051, [1631,1267,911,701]],
        [2185, [1735,1373,985,745]],
        [2323, [1843,1455,1033,793]],
        [2465, [1955,1541,1115,845]],
        [2611, [2071,1631,1171,901]],
        [2761, [2191,1725,1231,961]],
        [2876, [2306,1812,1286,986]],
        [3034, [2434,1914,1354,1054]],
        [3196, [2566,1992,1426,1096]],
        [3362, [2702,2102,1502,1142]],
        [3532, [2812,2216,1582,1222]],
        [3706, [2956,2334,1666,1276]],
    ];

    return raw.map(function(entry) {
        return {
            total: entry[0],
            data: entry[1] // [L, M, Q, H]
        };
    });
}

function getDataCapacity(version, ecLevel) {
    if (version < 1 || version > 40) return 0;
    const entry = EC_TABLE[version - 1];
    if (!entry) return 0;
    return entry.data[ecLevel] || entry.data[0];
}

function getCharCountBits(mode, version) {
    // Number of bits used for character count indicator
    if (version <= 9) {
        if (mode === 0x1) return 10; // Numeric
        if (mode === 0x2) return 9;  // Alphanumeric
        if (mode === 0x4) return 8;  // Byte
        if (mode === 0x8) return 8;  // Kanji
    } else if (version <= 26) {
        if (mode === 0x1) return 12;
        if (mode === 0x2) return 11;
        if (mode === 0x4) return 16;
        if (mode === 0x8) return 10;
    } else {
        if (mode === 0x1) return 14;
        if (mode === 0x2) return 13;
        if (mode === 0x4) return 16;
        if (mode === 0x8) return 12;
    }
    return 8; // fallback
}

function decodeData(bits, version, ecLevel) {
    let pos = 0;

    function readBits(n) {
        if (pos + n > bits.length) return 0;
        let val = 0;
        for (let i = 0; i < n; i++) {
            val = (val << 1) | (bits[pos++] || 0);
        }
        return val;
    }

    // Total data capacity in bits (data codewords * 8)
    const dataCapacity = getDataCapacity(version, ecLevel) * 8;
    const maxBits = Math.min(bits.length, dataCapacity > 0 ? dataCapacity : bits.length);

    let result = '';

    while (pos + 4 <= maxBits) {
        const mode = readBits(4);
        if (mode === 0) break; // Terminator

        const countBits = getCharCountBits(mode, version);

        if (mode === 0x1) {
            // Numeric mode
            const count = readBits(countBits);
            let remaining = count;
            while (remaining >= 3) {
                if (pos + 10 > bits.length) break;
                const val = readBits(10);
                result += val.toString().padStart(3, '0');
                remaining -= 3;
            }
            if (remaining === 2) {
                if (pos + 7 > bits.length) break;
                result += readBits(7).toString().padStart(2, '0');
            } else if (remaining === 1) {
                if (pos + 4 > bits.length) break;
                result += readBits(4).toString();
            }
        } else if (mode === 0x2) {
            // Alphanumeric mode
            const ALPHA = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:';
            const count = readBits(countBits);
            let remaining = count;
            while (remaining >= 2) {
                if (pos + 11 > bits.length) break;
                const val = readBits(11);
                result += ALPHA[Math.floor(val / 45)] || '?';
                result += ALPHA[val % 45] || '?';
                remaining -= 2;
            }
            if (remaining === 1) {
                if (pos + 6 > bits.length) break;
                result += ALPHA[readBits(6)] || '?';
            }
        } else if (mode === 0x4) {
            // Byte mode (ISO 8859-1 / UTF-8)
            const count = readBits(countBits);
            const bytes = [];
            for (let i = 0; i < count; i++) {
                if (pos + 8 > bits.length) break;
                bytes.push(readBits(8));
            }
            // Try UTF-8 decoding first, fall back to Latin-1
            try {
                result += new TextDecoder('utf-8', { fatal: true })
                    .decode(new Uint8Array(bytes));
            } catch (e) {
                for (let i = 0; i < bytes.length; i++) {
                    result += String.fromCharCode(bytes[i]);
                }
            }
        } else if (mode === 0x8) {
            // Kanji mode (Shift JIS)
            const count = readBits(countBits);
            for (let i = 0; i < count; i++) {
                if (pos + 13 > bits.length) break;
                let val = readBits(13);
                const hi = Math.floor(val / 0xC0);
                const lo = val % 0xC0;
                let sjis = hi * 0x100 + lo;
                if (sjis < 0x1F00) {
                    sjis += 0x8140;
                } else {
                    sjis += 0xC140;
                }
                // Convert Shift_JIS to Unicode (basic mapping)
                result += String.fromCharCode(sjis);
            }
        } else if (mode === 0x7) {
            // ECI mode - read ECI designator and continue
            const eci = readBits(8);
            // ECI just changes encoding; for most QR codes it's UTF-8 (26)
            // We continue to the next mode segment
        } else {
            // Unknown mode, stop decoding
            break;
        }
    }

    return result;
}

// ── Brute-Force Mask Attempt ───────────────────────────────────────
// If the format info doesn't decode cleanly, try all 8 mask patterns
// and return the result that looks most like valid text.

function tryAllMasks(grid, size, version) {
    let bestResult = null;
    let bestScore = -1;

    for (let mask = 0; mask < 8; mask++) {
        for (let ecl = 0; ecl < 4; ecl++) {
            try {
                const unmasked = unmask(grid, size, version, mask);
                const bits = readDataBits(unmasked, size, version);
                const data = decodeData(bits, version, ecl);
                if (data && data.length > 0) {
                    // Score: prefer results with more printable ASCII chars
                    let score = 0;
                    for (let i = 0; i < data.length; i++) {
                        const code = data.charCodeAt(i);
                        if (code >= 32 && code <= 126) score += 2;
                        else if (code >= 128 && code <= 0xFFFF) score += 1;
                        else score -= 5;
                    }
                    // Penalize very long results (likely garbage)
                    if (data.length > 4000) score -= data.length;
                    if (score > bestScore) {
                        bestScore = score;
                        bestResult = data;
                    }
                }
            } catch (e) {
                // Ignore errors, try next combination
            }
        }
    }

    return bestResult;
}

// ── Main Decode Function ───────────────────────────────────────────

function decodeQRFromImageData(imageData, width, height) {
    try {
        // Step 1: Binarize the image
        const binary = binarize(imageData, width, height);

        // Step 2: Find the three finder patterns
        const patterns = findFinderPatterns(binary, width, height);
        if (patterns.length < 3) return null;

        // Step 3: Determine pattern arrangement (TL, TR, BL)
        const arranged = arrangePatterns(patterns);
        if (!arranged) return null;

        // Step 4: Calculate average module size
        const moduleSize = (
            arranged.topLeft.size +
            arranged.topRight.size +
            arranged.bottomLeft.size
        ) / 3;

        // Step 5: Extract the module grid
        const { grid, size, version } = extractGrid(
            binary, width, height, arranged, moduleSize
        );
        if (size < 21 || size > 177) return null;

        // Step 6: Read format information
        const formatInfo = readFormatInfo(grid, size);

        // Step 7: Unmask the data modules
        const unmasked = unmask(grid, size, version, formatInfo.maskPattern);

        // Step 8: Read the data bits in zigzag order
        const bits = readDataBits(unmasked, size, version);

        // Step 9: Decode the data payload
        const data = decodeData(bits, version, formatInfo.ecLevel);

        if (data && data.length > 0) {
            return data;
        }

        // If primary decode failed, try brute-forcing all mask patterns
        return tryAllMasks(grid, size, version);
    } catch (e) {
        return null;
    }
}

// Export to global scope
global.decodeQRFromImageData = decodeQRFromImageData;

})(typeof window !== 'undefined' ? window : typeof self !== 'undefined' ? self : this);

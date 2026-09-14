import * as fs from 'fs';
import * as path from 'path';
import * as vscode from 'vscode';

/**
 * What the installed application says about the server it expects.
 *
 * Every value comes from the application's own `product.json`, so the extension
 * follows whatever it is installed into rather than carrying its own idea of
 * where servers come from or what they are called.
 */
export interface ProductMetadata {
    readonly commit: string;
    readonly quality: string;
    readonly serverApplicationName: string;
    readonly serverDataFolderName: string;
    readonly serverDownloadUrlTemplate: string;
}

interface RawProduct {
    commit?: string;
    quality?: string;
    serverApplicationName?: string;
    serverDataFolderName?: string;
    serverDownloadUrlTemplate?: string;
    remote?: { SSH?: { serverDownloadUrlTemplate?: string } };
}

export class ProductMetadataError extends Error {}

export function readProductMetadata(): ProductMetadata {
    const productPath = path.join(vscode.env.appRoot, 'product.json');
    let raw: RawProduct;
    try {
        raw = JSON.parse(fs.readFileSync(productPath, 'utf8')) as RawProduct;
    } catch (err) {
        throw new ProductMetadataError(
            `could not read ${productPath}, so there is no way to know which remote server this build expects`,
        );
    }

    // The override is read from application scope only. A workspace must not be
    // able to redirect where the server is fetched from.
    const configured = vscode.workspace
        .getConfiguration('kiroRemoteSsh')
        .inspect<string>('serverDownloadUrlTemplate')?.globalValue;

    const template =
        (configured && configured.trim()) ||
        raw.remote?.SSH?.serverDownloadUrlTemplate ||
        raw.serverDownloadUrlTemplate;

    const missing: string[] = [];
    if (!raw.commit) {
        missing.push('commit');
    }
    if (!raw.serverApplicationName) {
        missing.push('serverApplicationName');
    }
    if (!raw.serverDataFolderName) {
        missing.push('serverDataFolderName');
    }
    if (!template) {
        missing.push('serverDownloadUrlTemplate');
    }
    if (missing.length > 0) {
        throw new ProductMetadataError(
            `this build does not publish ${missing.join(', ')} in product.json, so its remote server cannot be located`,
        );
    }

    return {
        commit: raw.commit!,
        quality: raw.quality ?? 'stable',
        serverApplicationName: raw.serverApplicationName!,
        serverDataFolderName: raw.serverDataFolderName!,
        serverDownloadUrlTemplate: template!,
    };
}

/**
 * Fill in the template. `${arch}` is deliberately left in place: the client does
 * not know the remote architecture, so the remote side substitutes it after
 * `uname -m`.
 */
export function serverDownloadUrl(product: ProductMetadata, os: 'linux'): string {
    return product.serverDownloadUrlTemplate
        .replace(/\$\{quality\}/g, product.quality)
        .replace(/\$\{commit\}/g, product.commit)
        .replace(/\$\{os\}/g, os);
}

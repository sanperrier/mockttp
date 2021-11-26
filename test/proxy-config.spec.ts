import { expect } from './test-utils';
import { matchesNoProxy } from '../src/rules/proxy-config';

describe("No-proxy parsing", () => {
    it("should not match an empty array", () => {
        expect(
            matchesNoProxy("example.org", 80, [])
        ).to.equal(false);
    });

    it("should not match an unrelated URL", () => {
        expect(
            matchesNoProxy("example.org", 80, ["google.com"])
        ).to.equal(false);
    });

    it("should not match an unrelated suffix", () => {
        expect(
            matchesNoProxy("example.org", 80, ["ple.com"])
        ).to.equal(false);
    });

    it("should match an exact match", () => {
        expect(
            matchesNoProxy("example.org", 80, ["example.org"])
        ).to.equal(true);
    });

    it("should match an exact match, ignoring leading dots", () => {
        expect(
            matchesNoProxy("example.org", 80, [".example.org"])
        ).to.equal(true);
    });

    it("should match an exact match, ignoring leading wildcards", () => {
        expect(
            matchesNoProxy("example.org", 80, ["*.example.org"])
        ).to.equal(true);
    });

    it("should match a subdomain", () => {
        expect(
            matchesNoProxy("subdomain.example.org", 80, ["example.org"])
        ).to.equal(true);
    });

    it("should match all ports if not specified", () => {
        expect(
            matchesNoProxy("example.org", 80, ["example.org"])
        ).to.equal(true);
    });

    it("should match specific port if specified", () => {
        expect(
            matchesNoProxy("example.org", 443, ["example.org:443"])
        ).to.equal(true);
    });

    it("should not match all ports if different port is specified", () => {
        expect(
            matchesNoProxy("example.org", 443, ["example.org:80"])
        ).to.equal(false);
    });

    it("should match IP addresses", () => {
        expect(
            matchesNoProxy("127.0.0.1", 80, ["127.0.0.1"])
        ).to.equal(true);
    });

    it("should not resolve IP addresses", () => {
        expect(
            matchesNoProxy("localhost", 80, ["127.0.0.1"])
        ).to.equal(false);
    });
});
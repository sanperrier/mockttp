import { CompletedRequest, getLocal, InitiatedRequest } from "../../..";
import { expect, fetch } from "../../test-utils";

describe("Request callback matching", function () {
    let server = getLocal();

    beforeEach(() => server.start());
    afterEach(() => server.stop());

    it("should match requests with the callback reports true", async () => {
        let initiatedRequest: InitiatedRequest | undefined;
        let completedRequestPromise: Promise<CompletedRequest> | undefined;
        await server.post('/abc').matching((initialied, request) => {
            initiatedRequest = initialied;
            completedRequestPromise = request;
            return true;
        }).thenReply(200, 'Mocked response');

        let result = await fetch(server.urlFor('/abc'), {
            method: 'POST',
            body: '{"username": "test", "passwd": "test"}'
        });

        const completedRequest = await completedRequestPromise;
        await expect(result).to.have.responseText('Mocked response');
        expect(initiatedRequest).to.haveOwnProperty('protocol', 'http');
        expect(completedRequest).to.haveOwnProperty('protocol', 'http');
        expect(initiatedRequest).to.haveOwnProperty('path', '/abc');
        expect(completedRequest).to.haveOwnProperty('path', '/abc');
        expect(await completedRequest?.body?.getJson()).to.deep.equal({ username: "test", passwd: "test" });
    });

    it("should match requests with an async callback", async () => {
        await server.post('/abc').matching(async (_, requestPromise) => {
            const request = await requestPromise;
            const body = await request?.body?.getJson() as any;
            return body?.username === 'test';
        }).thenReply(200, 'Mocked response');

        let result = await fetch(server.urlFor('/abc'), {
            method: 'POST',
            body: '{"username": "test", "passwd": "test"}'
        });

        await expect(result).to.have.responseText('Mocked response');
    });

    it("should not match requests with the callback reports false", async () => {
        await server.get('/abc').matching(() => {
            return false;
        }).thenReply(200, 'Mocked response');

        let result = await fetch(server.urlFor('/abc'));

        await expect(result).to.have.status(503);
    });

    it("should throw a Matcher exception if the callback throws an error", async () => {
        await server.get('/abc').matching(() => {
            throw new Error("Matcher exception");
        }).thenReply(200, 'Mocked response');

        const result = await fetch(server.urlFor('/abc'));

        await expect(result).to.have.status(500);
    });
});

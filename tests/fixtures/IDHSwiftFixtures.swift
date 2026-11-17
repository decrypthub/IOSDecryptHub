import Foundation

public typealias Notice = @convention(c) (UnsafeMutableRawPointer?, Int32, UInt64, Int64) -> Void
public typealias Gate = @convention(c) (UnsafeMutableRawPointer?) -> Int32
private final class Inputs: @unchecked Sendable {
    let opaque: UnsafeMutableRawPointer?
    let notice: Notice
    let gate: Gate
    init(_ opaque: UnsafeMutableRawPointer?, _ notice: @escaping Notice, _ gate: @escaping Gate) {
        self.opaque = opaque; self.notice = notice; self.gate = gate
    }
    func report(_ phase: Int32, _ value: Int64 = 0) {notice(opaque, phase, FixtureLocal.identity, value)}
    func wait() async throws {
        for _ in 0..<15000 {
            if gate(opaque) != 0 {return}
            try await Task.sleep(nanoseconds: 1_000_000)
        }
        throw FixtureError.timeout
    }
}
private enum FixtureLocal {@TaskLocal static var identity: UInt64 = 0}
private enum FixtureError: Error {case timeout, expected}
private let inputLock = NSLock()
private var sharedInputs: Inputs?
private func readInputs() -> Inputs? {
    inputLock.lock(); defer {inputLock.unlock()}; return sharedInputs
}
private func noCaptureBody() async -> Int64 {
    guard let input = readInputs() else {return -1}
    input.report(50)
    do {try await input.wait(); input.report(51); return 5}
    catch {input.report(59); return -1}
}
private func structuredBody(_ input: Inputs) async throws -> Int64 {
    input.report(40)
    try await input.wait()
    await Task.yield()
    input.report(41)
    return 4
}

@_cdecl("idh_swift_fixture_start")
public func fixtureStart(_ opaque: UnsafeMutableRawPointer?, _ notice: @escaping Notice, _ gate: @escaping Gate) -> Int32 {
    let input = Inputs(opaque, notice, gate)
    inputLock.lock(); sharedInputs = input; inputLock.unlock()
    Task.detached {
        await FixtureLocal.$identity.withValue(0x4848) {
            input.report(10)
            let inherited = Task {
                input.report(20)
                try await input.wait()
                await Task.yield()
                input.report(21)
                await MainActor.run {input.report(22)}
                return Int64(2)
            }
            let detached = Task.detached {
                input.report(30)
                try await input.wait()
                input.report(31)
                return Int64(3)
            }
            let empty = Task.detached(operation: noCaptureBody)
            let cancelled = Task<Int64, Error> {
                input.report(60)
                do {try await input.wait()}
                catch let error as CancellationError {
                    // Cancellation may wake the pending sleep before the gate
                    // loop resumes. Observe that real exit before rethrowing.
                    input.report(61, Task.isCancelled ? 1 : 0)
                    throw error
                }
                while !Task.isCancelled {await Task.yield()}
                input.report(61, 1)
                try Task.checkCancellation()
                return 0
            }
            let throwing = Task<Int64, Error> {
                input.report(70)
                try await input.wait()
                input.report(71)
                throw FixtureError.expected
            }
            async let structured = structuredBody(input)
            do {
                try await input.wait()
                cancelled.cancel()
                let total = try await inherited.value + detached.value + structured + empty.value
                do {_ = try await cancelled.value; input.report(99)}
                catch is CancellationError {input.report(14, 1)}
                do {_ = try await throwing.value; input.report(99)}
                catch FixtureError.expected {input.report(15, 1)}
                input.report(11, total)
                do {throw FixtureError.expected} catch FixtureError.expected {input.report(12)}
            } catch {input.report(99)}
        }
        input.report(13)
    }
    return 1
}

@_cdecl("idh_swift_fixture_fast")
public func fixtureFast(_ opaque: UnsafeMutableRawPointer?, _ notice: @escaping Notice, _ gate: @escaping Gate) -> Int32 {
    let input = Inputs(opaque, notice, gate)
    Task.detached {
        let tasks = (0..<64).map {index in
            Task.detached {
                input.notice(input.opaque, 80, FixtureLocal.identity, Int64(index))
                return Int64(index * 7 + 3)
            }
        }
        var sum: Int64 = 0
        for task in tasks {sum += await task.value}
        input.notice(input.opaque, 82, FixtureLocal.identity, sum)
    }
    return 1
}

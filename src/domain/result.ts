/**
 * A typed channel for expected success or failure (REA `src/domain/result.ts`).
 * There are no map/flatMap helpers: branch with `if (!r.ok) return r;`, which
 * type-checks because `Result<never, E>` is assignable to `Result<U, E>`.
 */
export type Result<T, E> = { readonly ok: true; readonly value: T } | { readonly ok: false; readonly error: E };

export const ok = <T>(value: T): Result<T, never> => ({ ok: true, value });

export const err = <E>(error: E): Result<never, E> => ({ ok: false, error });

/** Run a throwing function at a boundary and wrap its failure as a value. @public */
export const tryResult = <T, E>(run: () => T, wrap: (cause: unknown) => E): Result<T, E> => {
  try {
    return ok(run());
  } catch (cause: unknown) {
    return err(wrap(cause));
  }
};

/** Async variant of {@link tryResult}. @public */
export const tryResultAsync = async <T, E>(
  run: () => Promise<T>,
  wrap: (cause: unknown) => E,
): Promise<Result<T, E>> => {
  try {
    return ok(await run());
  } catch (cause: unknown) {
    return err(wrap(cause));
  }
};
